"""
HXRECON — Escáner TCP asíncrono / Async TCP Connect Scanner.

Implements a full TCP connect scan using asyncio-native sockets with
semaphore-controlled concurrency. No external binaries are invoked.
Every TCP connection is made through the stdlib ``asyncio.open_connection``
interface.

Results are streamed as ``ScanResult`` dataclass instances via an
``AsyncGenerator``, allowing the engine to process them in real-time
as ports are discovered.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

from hxrecon.core.config import ScannerConfig
from hxrecon.modules.opsec import OPSECLayer

logger = logging.getLogger(__name__)

# Common service port mappings (IANA-based subset)
SERVICE_MAP: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    465: "smtps",
    514: "syslog",
    587: "submission",
    593: "http-rpc-epmap",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks5",
    1194: "openvpn",
    1352: "lotusnotes",
    1433: "mssql",
    1521: "oracle-db",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3128: "squid",
    3306: "mysql",
    3389: "ms-wbt-server",
    3690: "svn",
    4333: "ahsp",
    4444: "metasploit-default",
    4786: "ciscosmartinstall",
    4848: "glassfish",
    5000: "upnp",
    5432: "postgresql",
    5555: "android-adb",
    5632: "pcanywhere",
    5900: "vnc",
    5901: "vnc-1",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6443: "kubernetes-api",
    6666: "irc",
    6667: "irc",
    6697: "ircs",
    7001: "weblogic",
    7070: "real-server",
    8000: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "sun-answerbook",
    9000: "cslistener",
    9001: "tor-orport",
    9042: "cassandra",
    9092: "kafka",
    9100: "hp-pdl-datastr",
    9200: "elasticsearch",
    9418: "git",
    9999: "distinct32",
    10000: "ndmp",
    11211: "memcached",
    27017: "mongod",
    27018: "mongod-shard",
    50070: "hdfs-namenode",
}


@dataclass
class ScanResult:
    """Result of a single port scan operation.

    Attributes:
        port: The target port number.
        state: Port state — one of "open", "closed", or "filtered".
        service: Guessed service name from port mapping, if available.
    """
    port: int
    state: str = "closed"
    service: str = ""

    def __post_init__(self) -> None:
        if not self.service:
            self.service = SERVICE_MAP.get(self.port, "")


class TCPScanner:
    """Asynchronous TCP connect scanner.

    Performs concurrent port scans using asyncio with a configurable
    semaphore to limit resource usage. Supports optional OPSEC
    countermeasures via the Ghost Protocol layer.

    Args:
        config: Scanner configuration dataclass.
        opsec: Optional OPSEC layer for evasion countermeasures.

    Example:
        config = ScannerConfig(target="10.0.0.1", ports=[22, 80, 443])
        scanner = TCPScanner(config)
        async for result in scanner.scan():
            print(f"Port {result.port}: {result.state}")
    """

    def __init__(
        self,
        config: ScannerConfig,
        opsec: Optional[OPSECLayer] = None,
    ) -> None:
        self.config = config
        self.opsec = opsec
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._host_resolved: Optional[str] = None
        self._scan_start_time: float = 0.0
        self._ports_completed: int = 0

    async def _resolve_target(self) -> str:
        """Resolve the target hostname to an IP address.

        Uses the event loop's ``getaddrinfo`` for non-blocking resolution.
        Caches the result for the lifetime of the scan.

        Returns:
            Resolved IP address string.

        Raises:
            OSError: If name resolution fails.
        """
        if self._host_resolved:
            return self._host_resolved
        try:
            addrinfo = await asyncio.get_event_loop().getaddrinfo(
                self.config.target, None, family=socket.AF_INET
            )
            self._host_resolved = addrinfo[0][4][0]
        except OSError:
            # Fallback: try IPv6
            try:
                addrinfo = await asyncio.get_event_loop().getaddrinfo(
                    self.config.target, None, family=socket.AF_INET6
                )
                self._host_resolved = addrinfo[0][4][0]
            except OSError as exc:
                logger.error("DNS resolution failed for %s: %s", self.config.target, exc)
                raise
        logger.debug("Resolved %s -> %s", self.config.target, self._host_resolved)
        return self._host_resolved

    async def _probe_port(self, port: int) -> ScanResult:
        """Attempt a TCP connection to a single port.

        Args:
            port: The port number to probe.

        Returns:
            A ``ScanResult`` with the determined port state.

        Raises:
            Does not raise; all connection errors are mapped to states.
        """
        host = await self._resolve_target()
        try:
            async with self._semaphore:
                if self.opsec:
                    await self.opsec.full_delay()

                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.config.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return ScanResult(port=port, state="open")

        except asyncio.TimeoutError:
            return ScanResult(port=port, state="filtered")
        except ConnectionRefusedError:
            return ScanResult(port=port, state="closed")
        except OSError as exc:
            if isinstance(exc, ConnectionResetError):
                return ScanResult(port=port, state="closed")
            if isinstance(exc, PermissionError):
                return ScanResult(port=port, state="filtered")
            logger.debug("Port %d: OSError %s", port, exc)
            return ScanResult(port=port, state="filtered")

    async def scan(self) -> AsyncGenerator[ScanResult, None]:
        """Execute the full port scan, yielding results as they arrive.

        Creates an asyncio task for each port, collects results in
        completion order, and yields them to the caller for real-time
        processing.

        Yields:
            ``ScanResult`` instances as each port probe completes.

        Raises:
            asyncio.CancelledError: If the scan is cancelled externally.
        """
        host = await self._resolve_target()
        total = len(self.config.ports)
        logger.info("Starting scan of %s (%d ports)", host, total)

        pending = {
            asyncio.create_task(self._probe_port(port), name=f"scan:{port}")
            for port in self.config.ports
        }

        completed = 0
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    try:
                        result = task.result()
                        yield result
                    except (OSError, asyncio.TimeoutError) as exc:
                        logger.debug("Task failed unexpectedly: %s", exc)
                    completed += 1
                    self._ports_completed = completed
        except asyncio.CancelledError:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            raise

        logger.info("Scan complete: %d/%d ports processed", completed, total)
