"""
HXRECON — Consulta CVE / CVE Lookup Module.

Correlates identified service names and versions against the
NIST National Vulnerability Database (NVD) API v2 to discover
known vulnerabilities affecting the target software.

Rate limiting is enforced per NIST NVD API v2 guidelines:
    - Without API key:  5 requests per 30 seconds
    - With API key:    50 requests per 30 seconds

This module uses stdlib ``urllib.request`` dispatched via
``asyncio.to_thread`` to avoid blocking the event loop.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hxrecon.core.config import CVEConfig

logger = logging.getLogger(__name__)

NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_WINDOW: float = 30.0
RATE_LIMIT_MAX_WITHOUT_KEY: int = 5
RATE_LIMIT_MAX_WITH_KEY: int = 50

# CVSS severity thresholds
CVSS_SEVERITY: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "NONE"),
]


def _severity_label(score: float) -> str:
    """Map a CVSS score to a severity label.

    Args:
        score: CVSS v3 base score.

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
    """
    for threshold, label in CVSS_SEVERITY:
        if score >= threshold:
            return label
    return "NONE"


# Common service name mappings for NVD keyword search.
# Keys are normalized service names from banner fingerprinting.
# Values are NVD-compatible keyword search strings.
SERVICE_KEYWORD_MAP: dict[str, str] = {
    "ssh": "ssh",
    "openssh": "openssh",
    "apache": "apache http server",
    "nginx": "nginx",
    "iis": "microsoft iis",
    "http": "http",
    "https": "https",
    "ftp": "ftp",
    "smtp": "smtp",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "mssql": "microsoft sql server",
    "oracle-db": "oracle database",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "elasticsearch": "elasticsearch",
    "kafka": "apache kafka",
    "tomcat": "apache tomcat",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "nginx": "nginx",
    "vnc": "vnc",
    "squid": "squid",
    "memcached": "memcached",
    "cassandra": "apache cassandra",
}


@dataclass
class CVEResult:
    """A single CVE entry with relevant metadata.

    Attributes:
        id: CVE identifier (e.g. CVE-2023-XXXXX).
        description: Brief vulnerability description.
        cvss_score: CVSS v3 base score.
        severity: Severity label (CRITICAL, HIGH, etc.).
        published: Publication date string.
        exploitability: Attack vector and complexity summary.
    """
    id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    severity: str = "NONE"
    published: str = ""
    exploitability: str = ""


@dataclass
class CVELookupResult:
    """Aggregated CVE lookup results.

    Attributes:
        service: The queried service name.
        version: The queried version string.
        cves: List of identified CVE records.
        total_count: Total matching CVEs from the API.
        error: Error message if the request failed.
    """
    service: str = ""
    version: str = ""
    cves: List[CVEResult] = field(default_factory=list)
    total_count: int = 0
    error: str = ""


class RateLimiter:
    """Token-bucket rate limiter for API requests.

    Args:
        max_requests: Maximum requests allowed per window.
        window: Time window in seconds.
    """

    def __init__(self, max_requests: int, window: float = RATE_LIMIT_WINDOW) -> None:
        self._max = max_requests
        self._window = window
        self._timestamps: list[float] = []

    async def acquire(self) -> None:
        """Block until a request slot is available.

        Waits if the number of requests in the current window has
        reached the limit. Sleeps until the oldest request expires.
        """
        now = time.monotonic()
        cutoff = now - self._window

        # Prune expired timestamps
        self._timestamps = [t for t in self._timestamps if t > cutoff]

        if len(self._timestamps) >= self._max:
            wait = self._timestamps[0] + self._window - now
            if wait > 0:
                logger.debug("Rate limit reached, waiting %.1fs", wait)
                await asyncio.sleep(wait)
            self._timestamps = [t for t in self._timestamps if t > time.monotonic() - self._window]

        self._timestamps.append(time.monotonic())

    @property
    def remaining(self) -> int:
        """Return the number of requests remaining in the current window."""
        now = time.monotonic()
        cutoff = now - self._window
        active = sum(1 for t in self._timestamps if t > cutoff)
        return max(0, self._max - active)


class CVELookup:
    """NIST NVD API v2 CVE correlator.

    Queries the NVD for known vulnerabilities matching a given
    service name and version. Enforces NIST rate limits.

    Args:
        config: CVE lookup configuration.

    Example:
        lookup = CVELookup(CVEConfig(service="openssh", version="8.9p1"))
        result = await lookup.search()
        for cve in result.cves:
            print(f"{cve.id}: {cve.severity} - {cve.description[:80]}")
    """

    def __init__(self, config: CVEConfig) -> None:
        self.config = config
        max_req = RATE_LIMIT_MAX_WITH_KEY if config.api_key else RATE_LIMIT_MAX_WITHOUT_KEY
        self._rate_limiter = RateLimiter(max_requests=max_req)
        self._user_agent = "HXRECON/1.0 (vulnerability-research)"

    def _build_url(self, keyword: str, version: str) -> str:
        """Build the NVD API v2 URL for a keyword + version search.

        Args:
            keyword: Service search keyword.
            version: Version string to match.

        Returns:
            Fully qualified NVD API URL with query parameters.
        """
        params: dict[str, str] = {
            "keywordSearch": f"{keyword} {version}",
            "keywordExactMatch": "true",
            "resultsPerPage": "20",
            "startIndex": "0",
        }
        return f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        """Send an HTTP GET request to the NVD API.

        Runs the synchronous request in a thread to avoid blocking
        the event loop.

        Args:
            url: Full NVD API URL.

        Returns:
            Parsed JSON response dict, or None on failure.
        """
        await self._rate_limiter.acquire()

        def _request() -> Optional[Dict[str, Any]]:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": self._user_agent,
                    "Accept": "application/json",
                },
            )
            if self.config.api_key:
                req.add_header("apiKey", self.config.api_key)

            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                logger.warning("NVD API HTTP %d: %s", exc.code, exc.reason)
                return None
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                logger.warning("NVD API request failed: %s", exc)
                return None

        return await asyncio.to_thread(_request)

    def _parse_cve(self, vuln: Dict[str, Any]) -> Optional[CVEResult]:
        """Extract a CVEResult from a NVD API vulnerability object.

        Args:
            vuln: Single vulnerability dict from the API response.

        Returns:
            Parsed CVEResult, or None if the entry is malformed.
        """
        try:
            cve_id = vuln.get("id", "")
            if not cve_id:
                cve_id = vuln.get("cve", {}).get("id", "")

            descriptions = (
                vuln.get("cve", {})
                .get("descriptions", [])
            )
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = vuln.get("cve", {}).get("metrics", {})
            cvss_score = 0.0
            exploitability = ""

            # Prefer CVSS v3.1, fallback to v3.0, then v2
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    vector = cvss_data.get("vectorString", "")
                    exploitability = vector
                    break

            published = vuln.get("cve", {}).get("published", "")

            return CVEResult(
                id=cve_id,
                description=description[:300],
                cvss_score=cvss_score,
                severity=_severity_label(cvss_score),
                published=published[:10] if published else "",
                exploitability=exploitability,
            )
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            logger.debug("Failed to parse CVE entry: %s", exc)
            return None

    async def search(
        self, service: Optional[str] = None, version: Optional[str] = None
    ) -> CVELookupResult:
        """Search for CVEs matching a service and version.

        Args:
            service: Service name to search for (overrides config).
            version: Version to match (overrides config).

        Returns:
            CVELookupResult with matched CVE entries.
        """
        svc = (service or self.config.service).strip().lower()
        ver = (version or self.config.version).strip()

        result = CVELookupResult(service=svc, version=ver)

        # Normalize service name for NVD keyword search
        keyword = SERVICE_KEYWORD_MAP.get(svc, svc)
        if not keyword:
            result.error = f"No search keyword for service: {svc}"
            return result

        url = self._build_url(keyword, ver)
        logger.debug("NVD query: %s", url)

        data = await self._fetch(url)
        if data is None:
            result.error = "NVD API request failed"
            return result

        vulnerabilities = data.get("vulnerabilities", [])
        result.total_count = data.get("totalResults", len(vulnerabilities))

        for vuln in vulnerabilities:
            parsed = self._parse_cve(vuln)
            if parsed:
                result.cves.append(parsed)

        # Sort by CVSS score descending
        result.cves.sort(key=lambda c: c.cvss_score, reverse=True)
        return result

    async def search_bulk(
        self, services: List[Dict[str, str]]
    ) -> List[CVELookupResult]:
        """Search for CVEs for multiple services concurrently.

        Each service dict must have "service" and "version" keys.
        Rate limiting is shared across all requests.

        Args:
            services: List of service/version dicts.

        Returns:
            List of CVELookupResult objects in the same order.
        """
        tasks = [self.search(s.get("service"), s.get("version")) for s in services]
        return await asyncio.gather(*tasks)
