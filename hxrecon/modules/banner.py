"""
HXRECON — Captura de banners / Banner Grabbing & Fingerprinting.

Connects to open TCP ports, sends protocol-appropriate probes, and
captures service banners. Uses regex-based fingerprinting to identify
service names and versions from banner text. Supports SSL/TLS wrapping
for services expected to use encryption.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

from hxrecon.core.config import BannerConfig

logger = logging.getLogger(__name__)

# Probe payloads keyed by common service ports.
# These are protocol-appropriate initial bytes that elicit a banner
# response from the listening service.
PROBE_PAYLOADS: dict[int, bytes] = {
    21: b"",                         # FTP — server sends banner on connect
    22: b"",                         # SSH — server sends banner on connect
    23: b"",                         # Telnet
    25: b"EHLO scan\r\n",            # SMTP
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"",                        # POP3 — server sends banner on connect
    143: b"",                        # IMAP — server sends banner on connect
    443: b"",                        # HTTPS — SSL handshake then optional GET
    445: b"",                        # SMB — raw, embedded in protocol
    993: b"",                        # IMAPS
    995: b"",                        # POP3S
    1433: b"",                       # MSSQL
    3306: b"",                       # MySQL
    3389: b"",                       # RDP
    5432: b"",                       # PostgreSQL
    5900: b"",                       # VNC
    6379: b"PING\r\n",               # Redis
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"",                       # HTTPS-alt
    27017: b"",                      # MongoDB
}

# Service fingerprint regex patterns.
# Each pattern maps capture groups to "service" and optionally "version".
FINGERPRINTS: list[Tuple[Pattern[str], str, Optional[str]]] = [
    # SSH
    (re.compile(rb"SSH-([\d.]+)-(.+?)\r?\n"), "ssh", "version"),
    # FTP
    (re.compile(rb"220[- ](.+?)\s+FTP\s+server.*ready", re.IGNORECASE), "ftp", None),
    (re.compile(rb"220[- ](.+?)\s+\(.*\)"), "ftp", None),
    # SMTP
    (re.compile(rb"220[- ](.+?)\s+(.*?)\s+ESMTP", re.IGNORECASE), "smtp", "version"),
    (re.compile(rb"220[- ](.+?)\s+SMTP", re.IGNORECASE), "smtp", None),
    # HTTP
    (re.compile(rb"^HTTP/[\d.]+\s+\d+\s+(.+?)\r?\n", re.IGNORECASE), "http", None),
    (re.compile(rb"Server:\s*(.+?)\r?\n", re.IGNORECASE), "http", "version"),
    # POP3
    (re.compile(rb"^\+OK\s+(.+?)\s+ready"), "pop3", None),
    # IMAP
    (re.compile(rb"^\* OK\s+\[.*\]\s+(.+?)\s+IMAP", re.IGNORECASE), "imap", None),
    # MySQL
    (re.compile(rb"^\x4a\x00\x00\x00\x0a(.+?)\x00"), "mysql", None),
    (re.compile(rb"mysql_native_password"), "mysql", None),
    # PostgreSQL
    (re.compile(rb"^R\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"), "postgresql", None),
    # Redis
    (re.compile(rb"^\+PONG\r?\n"), "redis", None),
    (re.compile(rb"^-ERR.*unknown command"), "redis", None),
    # MongoDB
    (re.compile(rb"admin|ismaster|buildinfo", re.IGNORECASE), "mongodb", None),
    # OpenSSH banner
    (re.compile(rb"OpenSSH[_-]([\w._-]+)"), "openssh", "version"),
    # Apache
    (re.compile(rb"Apache(?:/([\d.]+))?", re.IGNORECASE), "apache", "version"),
    # nginx
    (re.compile(rb"nginx(?:/([\d.]+))?", re.IGNORECASE), "nginx", "version"),
    # IIS
    (re.compile(rb"Microsoft-IIS(?:/([\d.]+))?", re.IGNORECASE), "iis", "version"),
]

DEFAULT_PROBE: bytes = b"\r\n"


@dataclass
class BannerResult:
    """Result of a banner grab operation.

    Attributes:
        port: The target port.
        banner: Raw banner text (up to 1024 bytes, decoded).
        service: Identified service name from fingerprinting.
        version: Identified version string if available.
        ssl: Whether the connection used SSL/TLS.
    """
    port: int = 0
    banner: str = ""
    service: str = ""
    version: str = ""
    ssl: bool = False


class BannerGrabber:
    """Asynchronous banner grabber with regex fingerprinting.

    Connects to open TCP ports, sends protocol-appropriate probes,
    and identifies services from captured banner text. Supports
    SSL/TLS wrapping for encrypted services.

    Args:
        config: Banner grabbing configuration.

    Example:
        grabber = BannerGrabber(config)
        result = await grabber.grab("10.0.0.1", 22)
        print(f"{result.service} {result.version}: {result.banner}")
    """

    def __init__(self, config: BannerConfig) -> None:
        self.config = config
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._ssl_context_insecure: Optional[ssl.SSLContext] = None

    def _get_ssl_context(self, verify: bool = False) -> ssl.SSLContext:
        """Get or create a cached SSL context.

        Args:
            verify: Whether to verify server certificates (default False for probes).

        Returns:
            Configured SSLContext.
        """
        if verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        return self._ssl_context

    def _fingerprint(self, banner: bytes, port: int) -> Tuple[str, str]:
        """Match banner bytes against known service fingerprints.

        Args:
            banner: Raw bytes captured from the service.
            port: Port number for fallback mapping.

        Returns:
            Tuple of (service_name, version_string).
        """
        for pattern, service, version_group in FINGERPRINTS:
            match = pattern.search(banner)
            if match:
                version = ""
                if version_group == "version" and match.lastindex and match.lastindex >= 1:
                    version = match.group(1).decode("utf-8", errors="replace")
                elif version_group is None and match.lastindex and match.lastindex >= 1:
                    # Use captured detail as version
                    version = match.group(1).decode("utf-8", errors="replace").strip()
                return service, version

        # Fallback: common port mapping
        port_map: dict[int, str] = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            27017: "mongodb",
        }
        svc = port_map.get(port, "unknown")
        return svc, ""

    def _get_probe(self, port: int, use_ssl: bool) -> bytes:
        """Select the probe payload for a given port.

        Args:
            port: Target port.
            use_ssl: Whether SSL is being used (adjusts HTTP probe).

        Returns:
            Probe bytes to send on connection.
        """
        if port in PROBE_PAYLOADS:
            payload = PROBE_PAYLOADS[port]
            if use_ssl and port in (80, 8080):
                # If SSL on HTTP ports, use HTTPS probe
                payload = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
            return payload
        return DEFAULT_PROBE

    async def grab(self, host: str, port: int) -> BannerResult:
        """Grab a banner from a single port.

        Connects, sends probe, reads response, fingerprints.

        Args:
            host: Target IP or hostname.
            port: Target port.

        Returns:
            BannerResult with captured data.
        """
        result = BannerResult(port=port)
        use_ssl = port in self.config.ssl_ports

        try:
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter

            if use_ssl:
                ssl_ctx = self._get_ssl_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=ssl_ctx, server_hostname=host
                    ),
                    timeout=self.config.timeout,
                )
                result.ssl = True
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.config.timeout,
                )

            # Send probe
            probe = self._get_probe(port, use_ssl)
            if probe:
                writer.write(probe)
                await writer.drain()

            # Read response
            banner_bytes = await asyncio.wait_for(
                reader.read(2048), timeout=self.config.timeout
            )

            writer.close()
            await writer.wait_closed()

            if banner_bytes:
                result.banner = banner_bytes.decode("utf-8", errors="replace").strip()
                result.service, result.version = self._fingerprint(banner_bytes, port)

        except asyncio.TimeoutError:
            result.banner = "[timeout]"
        except ConnectionRefusedError:
            result.banner = "[refused]"
        except ssl.SSLError as exc:
            result.banner = f"[ssl_error: {exc}]"
            result.service = "ssl-error"
        except OSError as exc:
            result.banner = f"[error: {exc}]"

        return result

    async def grab_many(
        self, host: str, ports: List[int]
    ) -> List[BannerResult]:
        """Grab banners from multiple ports concurrently.

        Args:
            host: Target IP or hostname.
            ports: List of ports to probe.

        Returns:
            List of BannerResult objects (one per port).
        """
        tasks = [asyncio.create_task(self.grab(host, p)) for p in ports]
        return await asyncio.gather(*tasks)
