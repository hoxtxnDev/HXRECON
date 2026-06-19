"""
HXRECON — Punto de entrada CLI / CLI Entry Point (Rich TUI).

Provides the command-line interface with cyberpunk aesthetic,
live scan progress display, and subcommand dispatch.

Subcommands / Subcomandos:
    scan    TCP port scan       (Escaneo de puertos TCP)
    dns     DNS reconnaissance  (Reconocimiento DNS)
    banner  Banner grabbing     (Captura de banners)
    cve     CVE lookup          (Consulta de vulnerabilidades)
    full    Run all modules     (Ejecutar todos los módulos)

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from hxrecon.core.config import (
    GlobalConfig,
    ScannerConfig,
    DNSConfig,
    BannerConfig,
    CVEConfig,
    OPSECConfig,
    parse_port_range,
)
from hxrecon.core.engine import ScanEngine, EngineResult
from hxrecon.modules.scanner import ScanResult
from hxrecon.modules.banner import BannerResult
from hxrecon.modules.dns_recon import DNSResult
from hxrecon.modules.cve import CVELookupResult

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# ASCII Banner
# ──────────────────────────────────────────────

BANNER = r"""
[bold magenta]  ██╗  ██╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
                 ╚██╗██╔╝╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
                 ╚███╔╝  ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
                 ██╔██╗  ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
                ██╔╝ ██╗██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
                ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/]

[bold cyan]  HXRECON v1.0.0 — Professional Network Reconnaissance Suite[/]
[dim]  Suite profesional de reconocimiento de red — ES/EN · © 2026 @hoxtxnDev[/]
"""


def _print_banner(console: Console, opsec_active: bool = False) -> None:
    """Print the ASCII banner to the console.

    Args:
        console: Rich Console instance.
        opsec_active: If True, append Ghost Protocol status.
    """
    console.print(BANNER)
    if opsec_active:
        console.print(
            "  [bold magenta]◆ GHOST PROTOCOL — ACTIVE[/]\n"
            "  [dim]  Jitter | Pacing | Decoy Noise | Source Port Rand.[/]\n"
        )
    else:
        console.print(
            "  [dim]◆ Ghost Protocol: DISABLED (use --opsec to enable)[/]\n"
        )


# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

def _setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure the Python logging system.

    Args:
        verbose: Enable INFO-level logging to stderr.
        debug: Enable DEBUG-level logging to stderr.
    """
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


# ──────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with subcommands.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="hxrecon",
        description="HXRECON — Professional Network Reconnaissance Suite (ES/EN)",
        epilog="Report issues: https://github.com/anomalyco/hxrecon/issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging / Registro detallado"
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Enable debug logging / Registro de depuración"
    )
    parser.add_argument(
        "--output-dir", "-o", default="", help="Output directory / Directorio de salida"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    scan_p = sub.add_parser("scan", help="TCP port scan / Escaneo de puertos TCP")
    scan_p.add_argument("-t", "--target", required=True, help="Target hostname or IP / Host o IP objetivo")
    scan_p.add_argument("-p", "--ports", required=True, help="Port range / Rango de puertos (e.g. 1-1000, 22,80,443)")
    scan_p.add_argument("--concurrency", type=int, default=500, help="Max concurrent tasks / Tareas concurrentes máx. (default: 500)")
    scan_p.add_argument("--timeout", type=float, default=3.0, help="Connection timeout / Tiempo de espera (default: 3.0s)")
    scan_p.add_argument("--opsec", action="store_true", help="Enable Ghost Protocol OPSEC layer / Activar capa OPSEC")
    scan_p.add_argument("--jitter-mean", type=float, default=0.5, help="Gaussian jitter mean / Media de jitter Gaussiano (s)")
    scan_p.add_argument("--jitter-std", type=float, default=0.15, help="Gaussian jitter std dev / Desviación estándar de jitter")
    scan_p.add_argument("--target-rate", type=float, default=10.0, help="Targets per second pacing / Objetivos por segundo")
    scan_p.add_argument("--decoy-noise", action="store_true", help="Interleave decoy DNS queries / Consultas DNS señuelo")
    scan_p.add_argument("--json", action="store_true", help="Export JSON results / Exportar resultados JSON")
    scan_p.add_argument("--md", action="store_true", help="Export Markdown results / Exportar resultados Markdown")

    # --- dns ---
    dns_p = sub.add_parser("dns", help="DNS reconnaissance / Reconocimiento DNS")
    dns_p.add_argument("-t", "--target", required=True, help="Target domain / Dominio objetivo")
    dns_p.add_argument("--wordlist", help="Path to subdomain wordlist / Ruta del wordlist de subdominios")
    dns_p.add_argument("--axfr", action="store_true", help="Attempt zone transfer / Intentar transferencia de zona")
    dns_p.add_argument("--resolver", default="1.1.1.1", help="Custom DNS resolver IP / Resolver DNS personalizado")
    dns_p.add_argument("--concurrency", type=int, default=50, help="Brute-force concurrency / Concurrencia de fuerza bruta")
    dns_p.add_argument("--json", action="store_true", help="Export results as JSON / Exportar JSON")
    dns_p.add_argument("--md", action="store_true", help="Export results as Markdown / Exportar Markdown")

    # --- banner ---
    banner_p = sub.add_parser("banner", help="Banner grabbing / Captura de banners")
    banner_p.add_argument("-t", "--target", required=True, help="Target hostname or IP / Host o IP objetivo")
    banner_p.add_argument("-p", "--ports", required=True, help="Port(s) to probe / Puertos a sondear (e.g. 22,80,443)")
    banner_p.add_argument("--timeout", type=float, default=3.0, help="Connection timeout / Tiempo de espera de conexión")
    banner_p.add_argument("--json", action="store_true", help="Export results as JSON / Exportar JSON")
    banner_p.add_argument("--md", action="store_true", help="Export results as Markdown / Exportar Markdown")

    # --- cve ---
    cve_p = sub.add_parser("cve", help="CVE lookup via NIST NVD / Consulta CVE en NIST NVD")
    cve_p.add_argument("--service", "-s", required=True, help="Service name / Nombre del servicio (e.g. openssh)")
    cve_p.add_argument("--version", "-ver", required=True, help="Version string / Versión (e.g. 8.9p1)")
    cve_p.add_argument("--api-key", help="NVD API key / Clave API de NVD (for higher rate limit)")
    cve_p.add_argument("--json", action="store_true", help="Export results as JSON / Exportar JSON")
    cve_p.add_argument("--md", action="store_true", help="Export results as Markdown / Exportar Markdown")

    # --- full ---
    full_p = sub.add_parser("full", help="Run all modules / Ejecutar todos los módulos")
    full_p.add_argument("-t", "--target", required=True, help="Target hostname or IP / Host o IP objetivo")
    full_p.add_argument("-p", "--ports", required=True, help="Port range / Rango de puertos")
    full_p.add_argument("--concurrency", type=int, default=500, help="Max concurrent tasks / Tareas concurrentes máx.")
    full_p.add_argument("--timeout", type=float, default=3.0, help="Connection timeout / Tiempo de espera")
    full_p.add_argument("--opsec", action="store_true", help="Enable Ghost Protocol / Activar Ghost Protocol")
    full_p.add_argument("--wordlist", help="DNS subdomain wordlist / Wordlist de subdominios")
    full_p.add_argument("--axfr", action="store_true", help="Attempt zone transfer / Intentar transferencia de zona")
    full_p.add_argument("--json", action="store_true", help="Export results as JSON / Exportar JSON")
    full_p.add_argument("--md", action="store_true", help="Export results as Markdown / Exportar Markdown")

    return parser


# ──────────────────────────────────────────────
# Config builders
# ──────────────────────────────────────────────

def _build_scan_config(args: argparse.Namespace) -> ScannerConfig:
    """Build ScannerConfig from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        ScannerConfig instance.
    """
    return ScannerConfig(
        target=args.target,
        ports=parse_port_range(args.ports),
        concurrency=args.concurrency,
        timeout=args.timeout,
        port_range_raw=args.ports,
    )


def _build_dns_config(args: argparse.Namespace) -> DNSConfig:
    """Build DNSConfig from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        DNSConfig instance.
    """
    return DNSConfig(
        target=args.target,
        wordlist_path=getattr(args, "wordlist", None),
        axfr=getattr(args, "axfr", False),
        resolver=args.resolver,
        concurrency=getattr(args, "concurrency", 50),
    )


def _build_banner_config(args: argparse.Namespace) -> BannerConfig:
    """Build BannerConfig from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        BannerConfig instance.
    """
    return BannerConfig(
        target=args.target,
        ports=parse_port_range(args.ports),
        timeout=args.timeout,
    )


def _build_cve_config(args: argparse.Namespace) -> CVEConfig:
    """Build CVEConfig from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        CVEConfig instance.
    """
    return CVEConfig(
        service=args.service,
        version=args.version,
        api_key=getattr(args, "api_key", None),
    )


def _build_opsec_config(args: argparse.Namespace) -> OPSECConfig:
    """Build OPSECConfig from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        OPSECConfig instance.
    """
    return OPSECConfig(
        enabled=getattr(args, "opsec", False),
        jitter_mean=getattr(args, "jitter_mean", 0.5),
        jitter_std=getattr(args, "jitter_std", 0.15),
        target_rate=getattr(args, "target_rate", 10.0),
        decoy_noise=getattr(args, "decoy_noise", False),
        randomize_source_ports=True,
    )


# ──────────────────────────────────────────────
# Scan command with Live TUI
# ──────────────────────────────────────────────

async def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the ``scan`` subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 = success).
    """
    if not RICH_AVAILABLE:
        print("Error: 'rich' is required for the TUI. Install with: pip install rich")
        return 1

    console = Console()
    _print_banner(console, opsec_active=args.opsec)

    config = GlobalConfig(
        scanner=_build_scan_config(args),
        opsec=_build_opsec_config(args),
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output_dir,
        export_json=args.json,
        export_md=args.md,
    )

    engine = ScanEngine(config)
    result = EngineResult()

    # Build the Live display layout
    layout = Layout()
    layout.split_column(
        Layout(name="status", size=12),
        Layout(name="feed", size=8),
        Layout(name="output", size=6),
    )

    status_panel = Panel(
        Text("Initializing scan... / Inicializando escaneo...", style="yellow"),
        title="[bold magenta]◆ HXRECON Scan Status — Estado del Escaneo[/]",
        border_style="magenta",
    )
    feed_panel = Panel(
        Text("Awaiting results... / Esperando resultados...", style="dim"),
        title="[bold cyan]◆ Live Results Feed — Resultados en Vivo[/]",
        border_style="cyan",
    )
    output_panel = Panel(
        Text("", style="dim"),
        title="[bold green]◆ Output / Salida[/]",
        border_style="green",
    )

    layout["status"].update(status_panel)
    layout["feed"].update(feed_panel)
    layout["output"].update(output_panel)

    start_time = time.monotonic()
    open_ports: List[ScanResult] = []
    feed_lines: List[str] = []

    def _update_display(elapsed: float) -> None:
        """Refresh the Live display panels."""
        total = len(config.scanner.ports)
        done = len(result.scan_results)
        pct = (done / total * 100) if total else 0.0
        rate = (done / elapsed) if elapsed > 0 else 0.0
        eta = (total - done) / rate if rate > 0 else 0.0

        status_text = Text()
        status_text.append(f"Target / Objetivo: ", style="bold")
        status_text.append(f"{config.scanner.target}\n", style="cyan")
        status_text.append(f"Ports / Puertos:   ", style="bold")
        status_text.append(f"{done}/{total} ({pct:.1f}%)\n", style="green")
        status_text.append(f"Open / Abiertos:   ", style="bold")
        status_text.append(f"{len(open_ports)}\n", style="green")
        status_text.append(f"Throughput / Rend.:", style="bold")
        status_text.append(f"{rate:.1f} ports/s\n", style="yellow")
        status_text.append(f"Elapsed / Trans.:  ", style="bold")
        status_text.append(f"{elapsed:.1f}s\n", style="cyan")
        if eta > 0:
            status_text.append(f"ETA / TME:         ", style="bold")
            status_text.append(f"{eta:.1f}s\n", style="cyan")
        status_text.append(f"Ghost Protocol:    ", style="bold")
        status_text.append(
            f"{'ACTIVE' if args.opsec else 'DISABLED'}\n",
            style="magenta" if args.opsec else "dim",
        )
        status_text.append(f"Concurrency / Con.:", style="bold")
        status_text.append(f"{args.concurrency}\n", style="cyan")

        layout["status"].update(
            Panel(status_text, title="[bold magenta]◆ HXRECON Status — Estado[/]", border_style="magenta")
        )

        # Mostrar últimas 6 líneas / Show last 6 feed lines
        display_lines = feed_lines[-6:]
        feed_text = Text()
        for line in display_lines:
            feed_text.append(line + "\n")
        layout["feed"].update(
            Panel(feed_text, title="[bold cyan]◆ Live Feed — Resultados en Vivo[/]", border_style="cyan")
        )

    def _on_result(scan_result: ScanResult, elapsed: float) -> None:
        """Callback invoked on each scan result (runs in event loop)."""
        result.scan_results.append(scan_result)
        if scan_result.state == "open":
            open_ports.append(scan_result)
            timestamp = time.strftime("%H:%M:%S")
            service_str = f" ({scan_result.service})" if scan_result.service else ""
            line = (
                f"[green]{timestamp}[/] Port [bold cyan]{scan_result.port}/tcp[/] "
                f"[green]OPEN[/]{service_str}"
            )
            feed_lines.append(line)
        _update_display(time.monotonic() - start_time)

    engine.set_callback(_on_result)

    try:
        with Live(
            layout, refresh_per_second=4, console=console, screen=True
        ):
            engine_result = await engine.run_scan()
            result.scan_results = engine_result.scan_results
            result.open_ports = engine_result.open_ports
            result.elapsed = engine_result.elapsed

        # Escaneo completo — mostrar resumen / Scan complete — show summary
        console.print("\n[bold green]═══ SCAN COMPLETE — ESCANEO COMPLETADO ═══[/]\n")

        # Tabla resumen / Summary table
        table = Table(title="Open Ports / Puertos Abiertos", border_style="green", box=box.ROUNDED)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", justify="center")
        table.add_column("Service", style="green")

        for r in open_ports:
            table.add_row(str(r.port), "[green]open[/]", r.service)

        if not open_ports:
            table.add_row("[yellow]No open ports found[/]", "", "")

        console.print(table)

        # Exportar resultados / Export results
        json_path, md_path = await engine.export_results(engine_result)
        if json_path:
            console.print(f"\n[green]✓[/] JSON report / Informe JSON: [cyan]{json_path}[/]")
        if md_path:
            console.print(f"[green]✓[/] Markdown report / Informe MD: [cyan]{md_path}[/]")

        # Mostrar archivos de salida / Show output directory contents
        output_files = []
        if os.path.isdir(config.output_dir):
            output_files = [
                f for f in os.listdir(config.output_dir)
                if f.startswith("hxrecon_") and f.endswith((".json", ".md"))
            ]
        if output_files:
            output_panel = Panel(
                Text("\n".join(f"  {f}" for f in output_files)),
                title="[bold green]Exported Files / Archivos Exportados[/]",
                border_style="green",
            )
            console.print(output_panel)

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted — Escaneo interrumpido. Flushing output...[/]")
        json_path, md_path = await engine.export_results(result)
        if json_path:
            console.print(f"[green]✓[/] Partial JSON / JSON parcial: [cyan]{json_path}[/]")

    return 0


# ──────────────────────────────────────────────
# DNS command
# ──────────────────────────────────────────────

async def _cmd_dns(args: argparse.Namespace) -> int:
    """Execute the ``dns`` subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 = success).
    """
    if not RICH_AVAILABLE:
        print("Error: 'rich' is required. Install: pip install rich")
        return 1

    console = Console()
    _print_banner(console)

    config = GlobalConfig(
        dns=_build_dns_config(args),
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output_dir,
        export_json=args.json,
        export_md=args.md,
    )

    engine = ScanEngine(config)

    try:
        with console.status("[bold cyan]◆ DNS Reconnaissance — Reconocimiento DNS...") as status:
            result = await engine.run_dns_recon()
    except KeyboardInterrupt:
        console.print("\n[red]Cancelled / Cancelado.[/]")
        return 1

    # Mostrar registros / Display records
    if result.records:
        table = Table(title=f"DNS Records / Registros DNS — {result.domain}", border_style="cyan", box=box.ROUNDED)
        table.add_column("Name / Nombre", style="green")
        table.add_column("Type / Tipo", style="yellow")
        table.add_column("Data / Datos", style="white")
        table.add_column("TTL", justify="right", style="dim")
        for r in result.records:
            table.add_row(r.name, r.type_name, r.data, str(r.ttl))
        console.print(table)
    else:
        console.print(f"[yellow]No DNS records found / Sin registros DNS: {result.domain}[/]")

    # Subdominios / Subdomains
    if result.subdomains:
        console.print(f"\n[bold green]Subdomains / Subdominios ({len(result.subdomains)}):[/]")
        sd_table = Table(box=box.SIMPLE)
        sd_table.add_column("FQDN", style="cyan")
        for sd in result.subdomains:
            sd_table.add_row(sd)
        console.print(sd_table)

    # AXFR — Transferencia de zona / Zone transfer
    if result.axfr_supported:
        console.print(f"\n[bold red]⚠ Zone transfer ENABLED / Transferencia de zona HABILITADA: {result.domain}[/]")
        if result.axfr_records:
            axfr_table = Table(title="AXFR Records / Registros AXFR", border_style="red", box=box.ROUNDED)
            axfr_table.add_column("Name / Nombre", style="green")
            axfr_table.add_column("Type / Tipo", style="yellow")
            axfr_table.add_column("Data / Datos", style="white")
            for r in result.axfr_records:
                axfr_table.add_row(r.name, r.type_name, r.data)
            console.print(axfr_table)

    # Exportar / Export
    if config.export_json or config.export_md:
        engine_result = EngineResult(dns_results=result)
        json_path, md_path = await engine.export_results(engine_result)
        if json_path:
            console.print(f"\n[green]✓[/] JSON: [cyan]{json_path}[/]")
        if md_path:
            console.print(f"[green]✓[/] MD:   [cyan]{md_path}[/]")

    return 0


# ──────────────────────────────────────────────
# Banner command
# ──────────────────────────────────────────────

async def _cmd_banner(args: argparse.Namespace) -> int:
    """Execute the ``banner`` subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 = success).
    """
    if not RICH_AVAILABLE:
        print("Error: 'rich' is required. Install: pip install rich")
        return 1

    console = Console()
    _print_banner(console)

    config = GlobalConfig(
        banner=_build_banner_config(args),
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output_dir,
        export_json=args.json,
        export_md=args.md,
    )

    engine = ScanEngine(config)

    try:
        with console.status("[bold cyan]◆ Grabbing banners — Capturando banners...") as status:
            results = await engine.run_banner_grab(ports=config.banner.ports)
    except KeyboardInterrupt:
        console.print("\n[red]Cancelled / Cancelado.[/]")
        return 1

    if results:
        table = Table(title=f"Banner Grabs — Captura de Banners: {args.target}", border_style="purple", box=box.ROUNDED)
        table.add_column("Port / Puerto", style="cyan", justify="right")
        table.add_column("Service / Servicio", style="green")
        table.add_column("Version / Versión", style="yellow")
        table.add_column("Banner", style="white", max_width=80)
        table.add_column("SSL", justify="center")

        for r in results:
            banner_trunc = r.banner[:70].replace("\n", " ").replace("\r", "")
            ssl_str = "[green]✓[/]" if r.ssl else "[dim]—[/]"
            table.add_row(str(r.port), r.service, r.version, banner_trunc, ssl_str)

        console.print(table)
    else:
        console.print("[yellow]No banners captured / Sin banners capturados.[/]")

    # Exportar / Export
    if config.export_json or config.export_md:
        engine_result = EngineResult(banner_results=results)
        json_path, md_path = await engine.export_results(engine_result)
        if json_path:
            console.print(f"\n[green]✓[/] JSON: [cyan]{json_path}[/]")
        if md_path:
            console.print(f"[green]✓[/] MD:   [cyan]{md_path}[/]")

    return 0


# ──────────────────────────────────────────────
# CVE command
# ──────────────────────────────────────────────

async def _cmd_cve(args: argparse.Namespace) -> int:
    """Execute the ``cve`` subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 = success).
    """
    if not RICH_AVAILABLE:
        print("Error: 'rich' is required. Install: pip install rich")
        return 1

    console = Console()
    _print_banner(console)

    config = GlobalConfig(
        cve=_build_cve_config(args),
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output_dir,
        export_json=args.json,
        export_md=args.md,
    )

    engine = ScanEngine(config)

    try:
        with console.status("[bold cyan]◆ Querying NIST NVD — Consultando base de datos NVD...") as status:
            results = await engine.run_cve_lookup()
    except KeyboardInterrupt:
        console.print("\n[red]Cancelled / Cancelado.[/]")
        return 1

    for res in results:
        if res.error:
            console.print(f"[red]Error: {res.error}[/]")
            continue

        console.print(f"\n[bold cyan]{res.service} {res.version}[/] — [yellow]{res.total_count} CVEs found / CVEs encontrados[/]")

        if res.cves:
            table = Table(border_style="red", box=box.ROUNDED)
            table.add_column("CVE ID", style="bold")
            table.add_column("Severity / Severidad")
            table.add_column("Score / Puntaje", justify="right")
            table.add_column("Published / Publicado")
            table.add_column("Description / Descripción", max_width=70)

            for cve in res.cves[:20]:
                sev_style = "red" if cve.severity == "CRITICAL" else "orange1" if cve.severity == "HIGH" else "yellow"
                table.add_row(
                    cve.id,
                    f"[{sev_style}]{cve.severity}[/]",
                    str(cve.cvss_score),
                    cve.published,
                    cve.description[:100],
                )
            console.print(table)

    # Exportar / Export
    if config.export_json or config.export_md:
        engine_result = EngineResult(cve_results=results)
        json_path, md_path = await engine.export_results(engine_result)
        if json_path:
            console.print(f"\n[green]✓[/] JSON: [cyan]{json_path}[/]")
        if md_path:
            console.print(f"[green]✓[/] MD:   [cyan]{md_path}[/]")

    return 0


# ──────────────────────────────────────────────
# Full command
# ──────────────────────────────────────────────

async def _cmd_full(args: argparse.Namespace) -> int:
    """Execute the ``full`` subcommand — run all modules.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 = success).
    """
    if not RICH_AVAILABLE:
        print("Error: 'rich' is required. Install: pip install rich")
        return 1

    console = Console()
    _print_banner(console, opsec_active=args.opsec)

    # Build all configs
    config = GlobalConfig(
        scanner=_build_scan_config(args),
        dns=DNSConfig(
            target=args.target,
            wordlist_path=getattr(args, "wordlist", None),
            axfr=getattr(args, "axfr", False),
        ),
        opsec=_build_opsec_config(args),
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output_dir,
        export_json=args.json,
        export_md=args.md,
    )

    engine = ScanEngine(config)

    console.print("[bold cyan]═══ Full Recon Suite — Suite Completa de Reconocimiento ═══[/]\n")

    try:
        # Fase 1 / Phase 1: Escaneo de puertos / Port scan
        console.print("[bold]Phase 1/3 — Fase 1/3:[/] [cyan]Port Scan / Escaneo de Puertos[/]")
        scan_result = await engine.run_scan()

        open_ports = scan_result.open_ports
        if open_ports:
            table = Table(border_style="green", box=box.SIMPLE)
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("Service", style="green")
            for r in open_ports:
                table.add_row(str(r.port), r.service)
            console.print(table)
        else:
            console.print("[yellow]  No open ports found.[/]")

        # Fase 2 / Phase 2: Captura de banners / Banner grab
        if open_ports:
            console.print(f"\n[bold]Phase 2/3 — Fase 2/3:[/] [purple]Banner Grabbing / Captura de Banners ({len(open_ports)} puertos)[/]")
            ports = [p.port for p in open_ports]
            banner_results = await engine.run_banner_grab(ports=ports)
            scan_result.banner_results = banner_results

            b_table = Table(border_style="purple", box=box.SIMPLE)
            b_table.add_column("Port", style="cyan", justify="right")
            b_table.add_column("Service", style="green")
            b_table.add_column("Version", style="yellow")
            for r in banner_results:
                b_table.add_row(str(r.port), r.service, r.version)
            console.print(b_table)
        else:
            banner_results = []
            console.print("[dim]  Skipping banner grab (no open ports).[/]")

        # Fase 3 / Phase 3: Consulta CVE / CVE lookup
        if banner_results:
            services = [
                {"service": r.service, "version": r.version}
                for r in banner_results if r.service
            ]
            if services:
                console.print(f"\n[bold]Phase 3/3 — Fase 3/3:[/] [red]CVE Lookup / Consulta CVE ({len(services)} servicios)[/]")
                cve_results = await engine.run_cve_lookup(services=services)
                scan_result.cve_results = cve_results

                for res in cve_results[:5]:
                    highest = res.cves[0] if res.cves else None
                    if highest:
                        console.print(
                            f"  [red]{highest.id}[/] ({highest.severity}, "
                            f"score {highest.cvss_score}) — {highest.description[:80]}"
                        )
                    else:
                        console.print(f"  [dim]{res.service} {res.version}: No CVEs found[/]")

        # Exportar / Export
        console.print(f"\n[bold green]═══ FULL RECON COMPLETE — RECONOCIMIENTO COMPLETO ═══[/]")
        json_path, md_path = await engine.export_results(scan_result)
        if json_path:
            console.print(f"[green]✓[/] JSON report / Informe JSON: [cyan]{json_path}[/]")
        if md_path:
            console.print(f"[green]✓[/] MD report / Informe MD:   [cyan]{md_path}[/]")
        console.print(f"[dim]Elapsed / Transcurrido: {scan_result.elapsed:.1f}s[/]")

    except KeyboardInterrupt:
        console.print("\n[red]Full recon interrupted — Reconocimiento interrumpido. Exporting partial results...[/]")
        if 'scan_result' in dir():
            json_path, md_path = await engine.export_results(scan_result)

    return 0


# ──────────────────────────────────────────────
# Async main dispatcher
# ──────────────────────────────────────────────

def main() -> None:
    """Synchronous entry point for the CLI.

    Parses arguments, sets up logging, and dispatches to the
    appropriate async subcommand handler.
    """
    parser = _build_parser()
    args = parser.parse_args()

    _setup_logging(verbose=args.verbose, debug=args.debug)

    # Map subcommand to handler
    handlers: dict[str, Any] = {
        "scan": _cmd_scan,
        "dns": _cmd_dns,
        "banner": _cmd_banner,
        "cve": _cmd_cve,
        "full": _cmd_full,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        exit_code = asyncio.run(handler(args))
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
