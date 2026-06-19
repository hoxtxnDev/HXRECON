"""
HXRECON — Motor de orquestación / Scan Orchestration Engine.

The ``ScanEngine`` class is the central coordinator that:

    1. Accepts a ``GlobalConfig`` and wires together all modules.
    2. Manages task lifecycle (cancellation, graceful shutdown).
    3. Collects results from each module and feeds them to the
       output pipeline (JSON, Markdown, Live display).
    4. Handles ``KeyboardInterrupt`` by cancelling pending tasks
       and flushing buffered output before exit.

Usage::

    config = GlobalConfig(scanner=ScannerConfig(target="10.0.0.1", ...))
    engine = ScanEngine(config)
    results = await engine.run_scan()

The engine is designed to be consumed by both the TUI entrypoint
and programmatic API callers.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple

from hxrecon.core.config import GlobalConfig
from hxrecon.modules.scanner import ScanResult, TCPScanner
from hxrecon.modules.banner import BannerGrabber, BannerResult
from hxrecon.modules.dns_recon import DNSRecon, DNSResult
from hxrecon.modules.cve import CVELookup, CVELookupResult
from hxrecon.modules.opsec import OPSECLayer
from hxrecon.core.output import (
    export_json,
    export_markdown,
    build_scan_table,
    build_banner_table,
    build_cve_table,
)

logger = logging.getLogger(__name__)


# Callback type for real-time result streaming
ScanCallback = Callable[[ScanResult, float], None]


@dataclass
class EngineResult:
    """Aggregated result from a full scan operation.

    Attributes:
        scan_results: Port scan results.
        open_ports: Convenience list of open ScanResult items.
        banner_results: Banner grab results.
        dns_results: DNS reconnaissance result.
        cve_results: CVE lookup results.
        elapsed: Wall-clock time in seconds.
        json_path: Path to exported JSON file (empty if not exported).
        md_path: Path to exported Markdown file (empty if not exported).
        error: Top-level error message if the run failed.
    """
    scan_results: List[ScanResult] = field(default_factory=list)
    open_ports: List[ScanResult] = field(default_factory=list)
    banner_results: List[BannerResult] = field(default_factory=list)
    dns_results: Optional[DNSResult] = None
    cve_results: List[CVELookupResult] = field(default_factory=list)
    elapsed: float = 0.0
    json_path: str = ""
    md_path: str = ""
    error: str = ""


class ScanEngine:
    """Central scan orchestrator.

    Wires configuration to modules, manages async task lifecycle,
    collects results, and handles graceful cancellation.

    Args:
        config: Complete global configuration.

    Example:
        engine = ScanEngine(config)
        result = await engine.run_scan()
        for port in result.open_ports:
            print(f"{port.port}/tcp open {port.service}")
    """

    def __init__(self, config: GlobalConfig) -> None:
        self.config = config
        self._opsec = OPSECLayer(config.opsec) if config.opsec.enabled else None
        self._scanner = TCPScanner(config.scanner, opsec=self._opsec)
        self._banner_grabber = BannerGrabber(config.banner)
        self._dns_recon = DNSRecon(config.dns)
        self._cve_lookup = CVELookup(config.cve)
        self._task_group: set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()
        self._start_time: float = 0.0
        self._result_callback: Optional[ScanCallback] = None

    def set_callback(self, callback: ScanCallback) -> None:
        """Register a callback invoked for each completed scan result.

        The callback receives the ``ScanResult`` and the elapsed time
        in seconds since scan start. Used by the TUI for live updates.

        Args:
            callback: A callable accepting (ScanResult, float).
        """
        self._result_callback = callback

    def _handle_signal(self) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        logger.info("Shutdown signal received, cancelling pending tasks...")
        self._shutdown_event.set()

    async def run_scan(self) -> EngineResult:
        """Execute the port scan phase.

        Returns:
            EngineResult with scan results populated.

        Raises:
            asyncio.CancelledError: If the scan is cancelled externally.
        """
        result = EngineResult()
        self._start_time = time.monotonic()

        if not self.config.scanner.ports:
            result.error = "No ports specified for scan"
            return result

        logger.info(
            "Starting scan: %s (%d ports, concurrency=%d)",
            self.config.scanner.target,
            len(self.config.scanner.ports),
            self.config.scanner.concurrency,
        )

        scanner_gen = self._scanner.scan()
        try:
            async for scan_result in scanner_gen:
                result.scan_results.append(scan_result)
                if scan_result.state == "open":
                    result.open_ports.append(scan_result)
                    logger.info("OPEN: %d/tcp - %s", scan_result.port, scan_result.service)

                elapsed = time.monotonic() - self._start_time
                if self._result_callback:
                    self._result_callback(scan_result, elapsed)

                if self._shutdown_event.is_set():
                    logger.warning("Scan cancelled by user")
                    break

        except asyncio.CancelledError:
            logger.warning("Scan cancelled")
            result.error = "Scan cancelled"
        except GeneratorExit:
            pass
        except Exception as exc:
            logger.exception("Scan failed: %s", exc)
            result.error = str(exc)
        finally:
            await scanner_gen.aclose()

        result.elapsed = time.monotonic() - self._start_time
        return result

    async def run_banner_grab(self, ports: Optional[List[int]] = None) -> List[BannerResult]:
        """Execute banner grabbing on specified or all open ports.

        Args:
            ports: Specific ports to probe. If None, uses config banner ports.

        Returns:
            List of BannerResult objects.
        """
        target = self.config.banner.target or self.config.scanner.target
        ports = ports or self.config.banner.ports

        if not ports:
            logger.warning("No ports specified for banner grab")
            return []

        logger.info("Grabbing banners from %d ports on %s", len(ports), target)
        results = await self._banner_grabber.grab_many(target, ports)
        return results

    async def run_dns_recon(self, domain: Optional[str] = None) -> DNSResult:
        """Execute DNS reconnaissance.

        Args:
            domain: Domain to query. Falls back to dns config target.

        Returns:
            DNSResult with all discovered records.
        """
        domain = domain or self.config.dns.target
        if not domain:
            logger.warning("No domain specified for DNS recon")
            return DNSResult(error="No domain specified")

        logger.info("Running DNS recon on %s", domain)
        dns_result = await self._dns_recon.run(domain)
        return dns_result

    async def run_cve_lookup(
        self, services: Optional[List[Dict[str, str]]] = None
    ) -> List[CVELookupResult]:
        """Execute CVE lookups for identified services.

        Args:
            services: List of dicts with "service" and "version" keys.
                      If None, derives from open port service names.

        Returns:
            List of CVELookupResult objects.
        """
        if services is None:
            services = []

        if not services and self.config.cve.service and self.config.cve.version:
            services = [
                {"service": self.config.cve.service, "version": self.config.cve.version}
            ]

        if not services:
            logger.warning("No services to look up for CVEs")
            return []

        logger.info("Looking up CVEs for %d services", len(services))
        results = await self._cve_lookup.search_bulk(services)
        return results

    async def export_results(self, result: EngineResult) -> Tuple[str, str]:
        """Export scan results to JSON and/or Markdown.

        Checks the config export flags. If neither is set but opsec
        is enabled, exports both by default.

        Args:
            result: Engine result to export.

        Returns:
            Tuple of (json_path, md_path). Empty string if not exported.
        """
        json_path = ""
        md_path = ""
        target = self.config.scanner.target or self.config.dns.target

        do_json = self.config.export_json
        do_md = self.config.export_md

        if not do_json and not do_md and self.config.opsec.enabled:
            do_json = True
            do_md = True

        if do_json:
            json_path = export_json(
                output_dir=self.config.output_dir,
                scan_results=result.scan_results,
                banner_results=result.banner_results,
                dns_results=result.dns_results,
                cve_results=result.cve_results,
                target=target,
            )

        if do_md:
            md_path = export_markdown(
                output_dir=self.config.output_dir,
                scan_results=result.scan_results,
                banner_results=result.banner_results,
                dns_results=result.dns_results,
                cve_results=result.cve_results,
                target=target,
            )

        return json_path, md_path

    async def run_full(self) -> EngineResult:
        """Run all reconnaissance modules sequentially.

        Executes: scan -> banner grab -> DNS recon -> CVE lookup.
        Each phase passes results to the next where possible.

        Returns:
            Complete EngineResult with all phases populated.
        """
        result = await self.run_scan()

        if not result.error and result.open_ports:
            open_ports_list = [p.port for p in result.open_ports]
            result.banner_results = await self.run_banner_grab(ports=open_ports_list)

        dns_domain = self.config.dns.target or self.config.scanner.target
        if dns_domain:
            result.dns_results = await self.run_dns_recon(domain=dns_domain)

        if result.banner_results:
            services = [
                {"service": r.service, "version": r.version}
                for r in result.banner_results if r.service
            ]
            result.cve_results = await self.run_cve_lookup(services=services)

        json_path, md_path = await self.export_results(result)
        result.json_path = json_path
        result.md_path = md_path

        return result
