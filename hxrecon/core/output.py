"""
HXRECON — Exportación de resultados / Output Rendering & Export.

Handles:
    - JSON export      (structured machine-readable format)
    - Markdown export  (human-readable report / informe legible)
    - Rich TUI layout helpers for the Live display

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from hxrecon.modules.scanner import ScanResult
from hxrecon.modules.banner import BannerResult
from hxrecon.modules.dns_recon import DNSRecord, DNSResult
from hxrecon.modules.cve import CVEResult, CVELookupResult

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Serialization helpers
# ──────────────────────────────────────────────

def _dataclass_to_dict(obj: Any) -> Any:
    """Recursively convert a dataclass (or list of dataclasses) to a dict.

    Args:
        obj: A dataclass instance, list, or primitive value.

    Returns:
        JSON-serializable dict or value.
    """
    if is_dataclass(obj):
        result: dict[str, Any] = {}
        for field_name in obj.__dataclass_fields__:
            value = getattr(obj, field_name)
            result[field_name] = _dataclass_to_dict(value)
        return result
    if isinstance(obj, list):
        return [_dataclass_to_dict(item) for item in obj]
    return obj


# ──────────────────────────────────────────────
# JSON Export
# ──────────────────────────────────────────────

def export_json(
    output_dir: str,
    scan_results: Optional[List[ScanResult]] = None,
    banner_results: Optional[List[BannerResult]] = None,
    dns_results: Optional[DNSResult] = None,
    cve_results: Optional[List[CVELookupResult]] = None,
    target: str = "",
) -> str:
    """Export results to a JSON file.

    All provided result sets are bundled into a single JSON document
    with a timestamp and target metadata.

    Args:
        output_dir: Directory to write the file in.
        scan_results: List of port scan results.
        banner_results: List of banner grab results.
        dns_results: DNS reconnaissance result.
        cve_results: List of CVE lookup results.
        target: Target hostname or IP for metadata.

    Returns:
        Absolute path to the written JSON file.

    Raises:
        OSError: If the output directory cannot be written to.
    """
    os.makedirs(output_dir, exist_ok=True)
    filename = f"hxrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(output_dir, filename)

    data: dict[str, Any] = {
        "tool": "HXRECON",
        "version": "1.0.0",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    if scan_results:
        data["scan"] = {
            "open_ports": [
                {"port": r.port, "service": r.service}
                for r in scan_results if r.state == "open"
            ],
            "total_open": sum(1 for r in scan_results if r.state == "open"),
            "total_scanned": len(scan_results),
        }

    if banner_results:
        data["banners"] = [
            {
                "port": r.port,
                "banner": r.banner,
                "service": r.service,
                "version": r.version,
                "ssl": r.ssl,
            }
            for r in banner_results
        ]

    if dns_results:
        data["dns"] = {
            "domain": dns_results.domain,
            "records": [
                {"name": r.name, "type": r.type_name, "data": r.data, "ttl": r.ttl}
                for r in dns_results.records
            ],
            "subdomains": dns_results.subdomains,
            "axfr_supported": dns_results.axfr_supported,
        }

    if cve_results:
        data["cve"] = [
            {
                "service": r.service,
                "version": r.version,
                "total_found": r.total_count,
                "cves": [
                    {
                        "id": c.id,
                        "score": c.cvss_score,
                        "severity": c.severity,
                        "description": c.description,
                        "published": c.published,
                    }
                    for c in r.cves
                ],
            }
            for r in cve_results
        ]

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info("JSON report written: %s", filepath)
    return filepath


# ──────────────────────────────────────────────
# Markdown Export
# ──────────────────────────────────────────────

def export_markdown(
    output_dir: str,
    scan_results: Optional[List[ScanResult]] = None,
    banner_results: Optional[List[BannerResult]] = None,
    dns_results: Optional[DNSResult] = None,
    cve_results: Optional[List[CVELookupResult]] = None,
    target: str = "",
) -> str:
    """Export results to a Markdown report file.

    Args:
        output_dir: Directory to write the file in.
        scan_results: List of port scan results.
        banner_results: List of banner grab results.
        dns_results: DNS reconnaissance result.
        cve_results: List of CVE lookup results.
        target: Target identifier.

    Returns:
        Absolute path to the written Markdown file.

    Raises:
        OSError: If the output directory cannot be written to.
    """
    os.makedirs(output_dir, exist_ok=True)
    filename = f"hxrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = os.path.join(output_dir, filename)

    lines: list[str] = []
    lines.append(f"# HXRECON Reconnaissance Report")
    lines.append("")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Port scan section
    if scan_results:
        open_ports = [r for r in scan_results if r.state == "open"]
        lines.append("## Port Scan Results")
        lines.append("")
        lines.append(f"| Port | State | Service |")
        lines.append(f"|------|-------|---------|")
        for r in open_ports:
            lines.append(f"| {r.port} | open | {r.service} |")
        if not open_ports:
            lines.append("_No open ports discovered._")
        lines.append("")

    # Banner section
    if banner_results:
        lines.append("## Banner Grabbing")
        lines.append("")
        lines.append(f"| Port | Service | Version | Banner |")
        lines.append(f"|------|---------|---------|--------|")
        for r in banner_results:
            banner_trunc = r.banner[:80].replace("\r", "").replace("\n", " ")
            lines.append(
                f"| {r.port} | {r.service} | {r.version} | `{banner_trunc}` |"
            )
        lines.append("")

    # DNS section
    if dns_results:
        lines.append("## DNS Reconnaissance")
        lines.append("")
        lines.append(f"**Domain:** {dns_results.domain}")
        lines.append("")
        if dns_results.records:
            lines.append("### Records")
            lines.append("")
            lines.append(f"| Name | Type | Data | TTL |")
            lines.append(f"|------|------|------|-----|")
            for r in dns_results.records:
                lines.append(f"| {r.name} | {r.type_name} | {r.data} | {r.ttl} |")
            lines.append("")
        if dns_results.subdomains:
            lines.append("### Discovered Subdomains")
            lines.append("")
            for sd in dns_results.subdomains:
                lines.append(f"- `{sd}`")
            lines.append("")
        if dns_results.axfr_supported:
            lines.append("### Zone Transfer (AXFR)")
            lines.append("")
            lines.append("Zone transfer is **enabled** on this domain.")
            if dns_results.axfr_records:
                lines.append("")
                lines.append(f"| Name | Type | Data |")
                lines.append(f"|------|------|------|")
                for r in dns_results.axfr_records:
                    lines.append(f"| {r.name} | {r.type_name} | {r.data} |")
                lines.append("")

    # CVE section
    if cve_results:
        lines.append("## CVE Lookup")
        lines.append("")
        for result in cve_results:
            lines.append(f"### {result.service} {result.version}")
            lines.append("")
            if result.error:
                lines.append(f"_Error: {result.error}_")
                lines.append("")
                continue
            lines.append(f"**Total CVEs found:** {result.total_count}")
            lines.append("")
            if result.cves:
                lines.append(f"| CVE ID | Severity | Score | Description |")
                lines.append(f"|--------|----------|-------|-------------|")
                for cve in result.cves:
                    desc_trunc = cve.description[:100]
                    lines.append(
                        f"| {cve.id} | {cve.severity} | {cve.cvss_score} | {desc_trunc} |"
                    )
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by HXRECON v1.0.0_")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info("Markdown report written: %s", filepath)
    return filepath


# ──────────────────────────────────────────────
# Rich TUI helpers (fall back gracefully if rich is absent)
# ──────────────────────────────────────────────

def build_scan_table(results: List[ScanResult]) -> Any:
    """Build a Rich Table from scan results.

    Args:
        results: List of ScanResult objects.

    Returns:
        A rich.Table instance, or None if rich is unavailable.
    """
    if not RICH_AVAILABLE:
        return None
    table = Table(title="Scan Results", border_style="cyan")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("State", justify="center")
    table.add_column("Service", style="green")

    for r in results:
        state_style = "green" if r.state == "open" else "red" if r.state == "closed" else "yellow"
        table.add_row(str(r.port), f"[{state_style}]{r.state}[/]", r.service)

    return table


def build_banner_table(results: List[BannerResult]) -> Any:
    """Build a Rich Table from banner grab results.

    Args:
        results: List of BannerResult objects.

    Returns:
        A rich.Table instance, or None if rich is unavailable.
    """
    if not RICH_AVAILABLE:
        return None
    table = Table(title="Banner Grabs", border_style="purple")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Banner", style="white", max_width=60)

    for r in results:
        banner_trunc = r.banner[:60].replace("\n", " ").replace("\r", "")
        table.add_row(str(r.port), r.service, r.version, banner_trunc)

    return table


def build_cve_table(results: List[CVELookupResult]) -> Any:
    """Build a Rich Table from CVE lookup results.

    Args:
        results: List of CVELookupResult objects.

    Returns:
        A rich.Table instance, or None if rich is unavailable.
    """
    if not RICH_AVAILABLE:
        return None
    table = Table(title="CVE Summary", border_style="red")
    table.add_column("Service", style="cyan")
    table.add_column("CVE ID", style="yellow")
    table.add_column("Severity")
    table.add_column("Score", justify="right")

    for res in results:
        for cve in res.cves[:10]:  # top 10
            sev_style = "red" if cve.severity == "CRITICAL" else "orange1" if cve.severity == "HIGH" else "yellow"
            table.add_row(
                f"{res.service} {res.version}",
                cve.id,
                f"[{sev_style}]{cve.severity}[/]",
                str(cve.cvss_score),
            )
    return table


def build_status_panel(
    target: str,
    ports_total: int,
    ports_done: int,
    ports_open: int,
    opsec_active: bool,
    elapsed: float,
) -> Any:
    """Build the live status panel for the scan TUI.

    Args:
        target: Scan target.
        ports_total: Total ports to scan.
        ports_done: Completed port probes.
        ports_open: Open ports found so far.
        opsec_active: Whether Ghost Protocol is active.
        elapsed: Elapsed time in seconds.

    Returns:
        A rich.Panel instance.
    """
    if not RICH_AVAILABLE:
        return None

    pct = (ports_done / ports_total * 100) if ports_total else 0.0
    rate = (ports_done / elapsed) if elapsed > 0 else 0.0
    eta = (ports_total - ports_done) / rate if rate > 0 else 0.0

    text = Text()
    text.append(f"Target:           ", style="bold")
    text.append(f"{target}\n", style="cyan")
    text.append(f"Ports:            ", style="bold")
    text.append(f"{ports_done}/{ports_total} ({pct:.1f}%)\n", style="green")
    text.append(f"Open ports:       ", style="bold")
    text.append(f"{ports_open}\n", style="green")
    text.append(f"Throughput:       ", style="bold")
    text.append(f"{rate:.1f} ports/sec\n", style="yellow")
    text.append(f"Elapsed:          ", style="bold")
    text.append(f"{elapsed:.1f}s\n", style="cyan")
    if eta > 0:
        text.append(f"ETA:              ", style="bold")
        text.append(f"{eta:.1f}s\n", style="cyan")
    text.append(f"Ghost Protocol:   ", style="bold")
    text.append(f"{'ACTIVE' if opsec_active else 'DISABLED'}\n",
                 style="magenta" if opsec_active else "dim")
    text.append(f"Concurrency:      ", style="bold")
    text.append(f"500\n", style="cyan")

    return Panel(text, title="[bold magenta]HXRECON Scan Status[/]", border_style="magenta")


def build_results_panel() -> Any:
    """Build an empty results panel for the live feed.

    Returns:
        A rich.Panel instance.
    """
    if not RICH_AVAILABLE:
        return None
    return Panel(
        Text("Awaiting results...", style="dim"),
        title="[bold cyan]Live Results Feed[/]",
        border_style="cyan",
    )
