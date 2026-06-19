"""
Ghost Protocol — Capa OPSEC de evasión / OPSEC Evasion Layer.

Provides operational security primitives that reduce the scanning host's
detectability during reconnaissance engagements:

    1. Gaussian jitter      — Non-deterministic inter-probe delays
    2. Target pacing        — Rate-limited target throughput
    3. Decoy noise          — Interleaved benign DNS queries
    4. Source port rand.    — OS-level ephemeral port diversification
    5. TTL awareness        — Fingerprint mitigations (documented below)

© 2026 @hoxtxnDev — MIT License

────────────────────────────────────────────────────────────────────────
TTL FINGERPRINT AWARENESS
────────────────────────────────────────────────────────────────────────

The initial TTL value in outbound IP packets is set by the operating
system's network stack. Common defaults:

    Linux:       64
    macOS:       64
    Windows:    128
    Cisco:      255
    Solaris:    255
    FreeBSD:     64

A scanner that receives responses with TTL = 128 reveals that the target
(or an intermediate hop) is running a Windows host. Conversely, sending
packets with an atypical initial TTL (e.g., patching the socket to use
129 instead of 128) can mask the scanning host's OS.

Mitigation strategies:
    - Raw socket manipulation (requires root): patch TTL in IP header
      before transmission via IP_TTL / IPV6_UNICAST_HOPS.
    - VPN/proxy chaining: obscure originating TTL by routing through
      intermediate hops that decrement TTL organically.
    - Fragment injection: break scan probes into fragments that
      reassembly-layer inspection tools handle differently than
      standard OS stacks.

Current limitation (std socket API): Windows and most POSIX sockets
do not allow setting IP_TTL on a per-connection basis without raw
socket privileges. HXRECON logs the detected TTL for awareness but
does not modify it.
────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from typing import Optional

from hxrecon.core.config import OPSECConfig

logger = logging.getLogger(__name__)

# Public resolvers used for decoy noise traffic when Ghost Protocol
# decoy mode is active. Queries to these resolvers appear as
# legitimate DNS traffic in network logs.
_DECOY_RESOLVERS: list[str] = [
    "1.1.1.1",      # Cloudflare
    "8.8.8.8",      # Google
    "9.9.9.9",      # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
]

_DECOY_DOMAINS: list[str] = [
    "api.github.com",
    "docs.python.org",
    "cdn.cloudflare.com",
    "auth.example.com",
    "update.googleapis.com",
    "ocsp.digicert.com",
    "login.microsoftonline.com",
]


class OPSECLayer:
    """Ghost Protocol operational security layer.

    Wraps asynchronous scan operations with OPSEC countermeasures
    to reduce detectability during network reconnaissance.

    Args:
        config: OPSEC configuration dataclass.

    Attributes:
        config: The resolved OPSEC configuration.
        _last_probe_time: Timestamp of the last emitted probe.
        _decoy_index: Rolling index for decoy domain rotation.
    """

    def __init__(self, config: OPSECConfig) -> None:
        self.config = config
        self._last_probe_time: float = 0.0
        self._decoy_index: int = 0
        self._source_ports: list[int] = []
        self._source_port_index: int = 0

        if config.randomize_source_ports:
            self._source_ports = random.sample(
                range(49152, 65535), min(1024, 16383)
            )

    async def jitter(self) -> None:
        """Apply Gaussian-distributed sleep jitter.

        Introduces a non-deterministic delay with configurable mean and
        standard deviation. The delay is clamped to [0, mean * 3] to
        prevent pathological long pauses.

        Raises:
            asyncio.CancelledError: If the task is cancelled during sleep.
        """
        if not self.config.enabled:
            return
        delay = random.gauss(self.config.jitter_mean, self.config.jitter_std)
        delay = max(0.0, min(delay, self.config.jitter_mean * 3.0))
        await asyncio.sleep(delay)

    async def pace_target(self) -> None:
        """Enforce inter-target pacing based on configured rate.

        Limits the rate at which new targets are probed to avoid
        triggering rate-based detection mechanisms.

        The pacing delay is computed as:
            delay = (1.0 / target_rate) - elapsed_since_last_probe

        Raises:
            asyncio.CancelledError: If the task is cancelled during sleep.
        """
        if not self.config.enabled:
            return
        now = time.monotonic()
        if self._last_probe_time == 0.0:
            self._last_probe_time = now
            return

        interval = 1.0 / max(self.config.target_rate, 0.1)
        elapsed = now - self._last_probe_time
        wait = interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_probe_time = time.monotonic()

    async def decoy_query(self) -> None:
        """Send a benign DNS query to a public resolver.

        Interleaves legitimate-looking DNS traffic between scan probes
        to blend reconnaissance activity with normal network behavior.

        This is a fire-and-forget operation. Failures are logged at
        debug level and silently swallowed.

        Raises:
            asyncio.CancelledError: If the task is cancelled during I/O.
        """
        if not self.config.enabled or not self.config.decoy_noise:
            return

        resolver = random.choice(_DECOY_RESOLVERS)
        domain = _DECOY_DOMAINS[self._decoy_index % len(_DECOY_DOMAINS)]
        self._decoy_index += 1

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolver, 53),
                timeout=1.0,
            )
            # Build a minimal DNS query packet (std query, IN class, A record)
            tid = random.randint(0, 0xFFFF)
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            qname = b"".join(
                bytes([len(label)]) + label.encode("ascii", errors="ignore")
                for label in domain.split(".")
            ) + b"\x00"
            question = qname + struct.pack(">HH", 1, 1)
            writer.write(header + question)
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=1.0)
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
            logger.debug("Decoy DNS query to %s failed (expected).", resolver)

    def get_source_port(self) -> Optional[int]:
        """Return a randomized source port for socket binding.

        When source port randomization is enabled, returns a port from
        a pre-generated pool to avoid predictable ephemeral port patterns
        that some IDS/IPS systems track.

        Returns:
            A source port integer, or None if randomization is disabled.

        Example:
            sock.bind(("0.0.0.0", opsec.get_source_port() or 0))
        """
        if not self.config.enabled or not self._source_ports:
            return None
        port = self._source_ports[self._source_port_index % len(self._source_ports)]
        self._source_port_index += 1
        return port

    async def full_delay(self) -> None:
        """Apply jitter, pacing, and optionally a decoy query.

        Convenience wrapper that executes all enabled OPSEC
        countermeasures in sequence after each probe.
        """
        if not self.config.enabled:
            return
        await self.jitter()
        await self.pace_target()
        if random.random() < 0.15:
            await self.decoy_query()
