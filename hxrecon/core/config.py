"""
HXRECON — Sistema de configuración centralizado.
HXRECON — Centralized configuration system.

Dataclass-based configuration for all reconnaissance modules.
All runtime parameters originate here and flow outward to modules
via dependency injection through the ScanEngine.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ──────────────────────────────────────────────
# Analizador de rango de puertos / Port range parser
# ──────────────────────────────────────────────

_PORT_RANGE_RE = re.compile(
    r"^(\d+)(?:-(\d+))?(?:,(\d+)(?:-(\d+))?)*$"
)


def parse_port_range(port_spec: str) -> List[int]:
    """Parse a port range string into a sorted list of ports.

    Accepts formats:
        "80"           -> [80]
        "1-1000"       -> [1, 2, ..., 1000]
        "22,80,443"    -> [22, 80, 443]
        "1-100,443"    -> [1..100, 443]
        "1-10,20-30"   -> combined ranges

    Args:
        port_spec: Port range string from CLI argument.

    Returns:
        Sorted list of unique port integers.

    Raises:
        ValueError: If the format is malformed or port numbers are out of range.
    """
    ports: set[int] = set()
    # Split on commas first
    segments = port_spec.split(",")
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        range_match = re.match(r"^(\d+)-(\d+)$", seg)
        single_match = re.match(r"^(\d+)$", seg)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    f"Invalid port range: {seg}. Must be 1-65535, start <= end."
                )
            ports.update(range(start, end + 1))
        elif single_match:
            p = int(single_match.group(1))
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of range 1-65535.")
            ports.add(p)
        else:
            raise ValueError(f"Cannot parse port segment: {seg!r}")
    result = sorted(ports)
    if not result:
        raise ValueError("Port range resolved to empty list.")
    return result


# ──────────────────────────────────────────────
# Configuration dataclasses
# ──────────────────────────────────────────────


@dataclass
class OPSECConfig:
    """Ghost Protocol operational security configuration.

    Attributes:
        enabled: Master switch for OPSEC layer.
        jitter_mean: Mean delay in seconds for Gaussian jitter.
        jitter_std: Standard deviation for Gaussian jitter.
        target_rate: Maximum targets per second for pacing.
        decoy_noise: Interleave decoy DNS queries when True.
        randomize_source_ports: Randomize ephemeral source ports when True.
    """
    enabled: bool = False
    jitter_mean: float = 0.5
    jitter_std: float = 0.15
    target_rate: float = 10.0
    decoy_noise: bool = False
    randomize_source_ports: bool = True


@dataclass
class ScannerConfig:
    """TCP connect scan configuration.

    Attributes:
        target: Single hostname or IP address to scan.
        ports: Resolved list of target ports.
        concurrency: Maximum concurrent asyncio tasks.
        timeout: Connection timeout in seconds.
        retries: Connection retry count on transient failure.
        port_range_raw: Original port spec string for display.
    """
    target: str = ""
    ports: List[int] = field(default_factory=list)
    concurrency: int = 500
    timeout: float = 3.0
    retries: int = 1
    port_range_raw: str = ""


@dataclass
class DNSConfig:
    """DNS reconnaissance configuration.

    Attributes:
        target: Target domain.
        wordlist_path: Optional path to subdomain wordlist.
        axfr: Attempt zone transfer when True.
        resolver: Custom DNS resolver IP (empty = system default).
        concurrency: Thread pool worker count for brute-force.
    """
    target: str = ""
    wordlist_path: Optional[str] = None
    axfr: bool = False
    resolver: Optional[str] = None
    concurrency: int = 50


@dataclass
class BannerConfig:
    """Banner grabbing configuration.

    Attributes:
        target: Target hostname or IP.
        ports: List of ports to probe.
        timeout: Per-connection timeout in seconds.
        ssl_ports: Ports to attempt SSL/TLS handshake first.
        probe_payloads: Dict mapping port to probe bytes.
    """
    target: str = ""
    ports: List[int] = field(default_factory=list)
    timeout: float = 3.0
    ssl_ports: List[int] = field(default_factory=lambda: [443, 8443, 465, 993, 995])


@dataclass
class CVEConfig:
    """CVE lookup configuration.

    Attributes:
        service: Service name (e.g. "openssh", "apache http server").
        version: Version string (e.g. "8.9p1", "2.4.49").
        api_key: Optional NVD API key for higher rate limits.
    """
    service: str = ""
    version: str = ""


@dataclass
class GlobalConfig:
    """Top-level configuration aggregating all sub-configs.

    Attributes:
        scanner: TCP scanner config.
        dns: DNS recon config.
        banner: Banner grab config.
        cve: CVE lookup config.
        opsec: OPSEC layer config.
        verbose: Enable verbose logging.
        debug: Enable debug-level logging.
        output_dir: Directory for output files.
        export_json: Export results as JSON when True.
        export_md: Export results as Markdown when True.
    """
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    banner: BannerConfig = field(default_factory=BannerConfig)
    cve: CVEConfig = field(default_factory=CVEConfig)
    opsec: OPSECConfig = field(default_factory=OPSECConfig)
    verbose: bool = False
    debug: bool = False
    output_dir: str = ""
    export_json: bool = False
    export_md: bool = False

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = os.path.join(os.getcwd(), "hxrecon_output")
