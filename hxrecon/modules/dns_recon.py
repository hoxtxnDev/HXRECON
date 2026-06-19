"""
HXRECON — Reconocimiento DNS / DNS Reconnaissance Module.

Performs DNS record enumeration (A, AAAA, MX, TXT, NS) and
subdomain brute-forcing using raw DNS packet construction over UDP.
No external DNS libraries (dnspython, etc.) are used — all wire
protocol is built and parsed with stdlib ``struct`` and ``asyncio``.

Zone transfer (AXFR) is attempted over TCP when requested.

© 2026 @hoxtxnDev — MIT License
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from hxrecon.core.config import DNSConfig

logger = logging.getLogger(__name__)

# DNS record type codes
QTYPE_A: int = 1
QTYPE_NS: int = 2
QTYPE_MX: int = 15
QTYPE_TXT: int = 16
QTYPE_AAAA: int = 28
QTYPE_AXFR: int = 252

QTYPE_NAMES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
    16: "TXT", 28: "AAAA", 252: "AXFR",
}

DEFAULT_RESOLVER: str = "1.1.1.1"
DNS_PORT: int = 53


def _encode_domain(domain: str) -> bytes:
    """Encode a domain name into DNS wire format (sequence of length-prefixed labels).

    Args:
        domain: Domain name (e.g. "example.com").

    Returns:
        Raw bytes in DNS label format (e.g. b"\\x07example\\x03com\\x00").
    """
    parts = domain.rstrip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode("ascii", errors="replace") for p in parts) + b"\x00"


def _decode_domain(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a DNS domain name from wire format, handling compression pointers.

    Args:
        data: Full DNS response packet bytes.
        offset: Starting offset of the domain name.

    Returns:
        Tuple of (decoded domain string, new offset after processing).
    """
    labels: list[bytes] = []
    jumped = False
    orig_offset = offset

    while offset < len(data):
        length = data[offset]
        if length & 0xC0:
            # Compression pointer (upper 2 bits set)
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length])
        offset += length

    if not jumped:
        return b".".join(labels).decode("ascii", errors="replace"), offset
    return b".".join(labels).decode("ascii", errors="replace"), orig_offset


def _build_dns_query(domain: str, qtype: int, tid: Optional[int] = None) -> bytes:
    """Build a DNS query packet.

    Args:
        domain: Target domain name.
        qtype: DNS record type (1=A, 15=MX, etc.).
        tid: Optional transaction ID (random if None).

    Returns:
        Complete DNS query packet as bytes.
    """
    tid = tid or random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = _encode_domain(domain)
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


def _parse_dns_response(data: bytes) -> List[Dict]:
    """Parse a DNS response packet and extract resource records.

    Handles A, AAAA, MX, TXT, NS, SOA, and CNAME records.
    Supports DNS name compression per RFC 1035.

    Args:
        data: Raw DNS response bytes (512+ bytes for UDP).

    Returns:
        List of parsed record dicts with keys: name, type, ttl, data.
    """
    if len(data) < 12:
        return []

    try:
        header = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return []
    tid, flags, qdcount, ancount, nscount, arcount = header
    offset = 12

    # Parse question section
    for _ in range(qdcount):
        _, offset = _decode_domain(data, offset)
        offset += 4  # skip qtype + qclass

    records: list[Dict] = []

    # Parse answer section
    for _ in range(ancount):
        if offset >= len(data):
            break
        name, offset = _decode_domain(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break

        rdata: str = ""
        if rtype == QTYPE_A and rdlength == 4:
            rdata = ".".join(str(data[offset + i]) for i in range(4))
        elif rtype == QTYPE_AAAA and rdlength == 16:
            rdata = ":".join(
                f"{(data[offset + i] << 8) | data[offset + i + 1]:x}"
                for i in range(0, 16, 2)
            )
        elif rtype == QTYPE_MX:
            preference = struct.unpack(">H", data[offset:offset + 2])[0]
            exchange, _ = _decode_domain(data, offset + 2)
            rdata = f"{preference} {exchange}"
        elif rtype == QTYPE_TXT:
            txt_parts: list[bytes] = []
            txt_offset = offset
            while txt_offset < offset + rdlength:
                txt_len = data[txt_offset]
                txt_offset += 1
                if txt_offset + txt_len <= offset + rdlength:
                    txt_parts.append(data[txt_offset:txt_offset + txt_len])
                    txt_offset += txt_len
                else:
                    break
            rdata = "".join(p.decode("utf-8", errors="replace") for p in txt_parts)
        elif rtype == QTYPE_NS:
            ns, _ = _decode_domain(data, offset)
            rdata = ns
        elif rtype == QTYPE_AXFR or rtype == QTYPE_SOA:
            if rdlength >= 20:
                mname, _ = _decode_domain(data, offset)
                rname, _ = _decode_domain(data, offset + (offset - data.find(b"\x00", offset)))
                try:
                    serial, refresh, retry, expire, minimum = struct.unpack(
                        ">IIIII", data[offset + (offset - data.find(b"\x00", offset)) + 2:offset + rdlength]
                    )
                    rdata = f"{mname} {rname} {serial}"
                except struct.error:
                    rdata = "<SOA>"
        else:
            rdata = f"<{rtype}: {data[offset:offset + rdlength].hex()}>"

        records.append({
            "name": name,
            "type": rtype,
            "type_name": QTYPE_NAMES.get(rtype, f"TYPE{rtype}"),
            "ttl": ttl,
            "data": rdata,
        })
        offset += rdlength

    return records


@dataclass
class DNSRecord:
    """A single resolved DNS record.

    Attributes:
        name: Fully qualified domain name.
        type_name: Record type name (A, MX, TXT, etc.).
        data: Record data payload.
        ttl: Time-to-live in seconds.
    """
    name: str = ""
    type_name: str = ""
    data: str = ""
    ttl: int = 0


@dataclass
class DNSResult:
    """Aggregated DNS reconnaissance results for a domain.

    Attributes:
        domain: The queried domain.
        records: All resolved DNS records.
        subdomains: Discovered subdomains.
        axfr_supported: Whether zone transfer succeeded.
        axfr_records: Zone transfer records if successful.
        error: Error message if the query failed.
    """
    domain: str = ""
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    axfr_supported: bool = False
    axfr_records: List[DNSRecord] = field(default_factory=list)
    error: str = ""


class DNSRecon:
    """DNS reconnaissance engine.

    Performs record lookups and subdomain brute-forcing using
    raw DNS-over-UDP queries built from stdlib primitives.

    Args:
        config: DNS configuration dataclass.
    """

    def __init__(self, config: DNSConfig) -> None:
        self.config = config
        self._resolver = config.resolver or DEFAULT_RESOLVER

    async def _query(self, domain: str, qtype: int, timeout: float = 3.0) -> List[Dict]:
        """Send a single DNS query via UDP and parse the response.

        Args:
            domain: Domain to query.
            qtype: DNS record type code.
            timeout: Response wait timeout in seconds.

        Returns:
            List of parsed resource record dicts.

        Raises:
            asyncio.TimeoutError: If no response within timeout.
            OSError: On network/socket errors.
        """
        packet = _build_dns_query(domain, qtype)
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(self._resolver, DNS_PORT),
        )

        try:
            protocol.sendto(packet)
            fut = asyncio.get_event_loop().create_future()

            class _Handler(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: Tuple) -> None:
                    if not fut.done():
                        fut.set_result(data)

                def error_received(self, exc: Exception) -> None:
                    if not fut.done():
                        fut.set_exception(exc)

            # We need to replace protocol; instead, use a simpler approach
            transport.close()

            # Direct UDP socket approach
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (self._resolver, DNS_PORT))
            data, _ = sock.recvfrom(512)
            sock.close()
            return _parse_dns_response(data)

        finally:
            if not transport.is_closing():
                transport.close()

    async def _query_udp_simple(self, domain: str, qtype: int, timeout: float = 3.0) -> List[Dict]:
        """Send DNS query via UDP using a simple synchronous-style socket in a thread.

        This approach avoids the complexity of asyncio datagram transports
        while remaining compatible with the event loop via ``run_in_executor``.

        Args:
            domain: Target domain.
            qtype: DNS record type code.
            timeout: Socket timeout in seconds.

        Returns:
            Parsed resource records.
        """
        loop = asyncio.get_event_loop()

        def _do_query() -> List[Dict]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                packet = _build_dns_query(domain, qtype)
                sock.sendto(packet, (self._resolver, DNS_PORT))
                data, _ = sock.recvfrom(512)
                return _parse_dns_response(data)
            finally:
                sock.close()

        return await loop.run_in_executor(None, _do_query)

    async def resolve_a(self, domain: str) -> List[DNSRecord]:
        """Resolve A (IPv4) records for a domain.

        Args:
            domain: Target domain.

        Returns:
            List of A record results.
        """
        try:
            records = await self._query_udp_simple(domain, QTYPE_A)
            return [
                DNSRecord(name=r["name"], type_name="A", data=r["data"], ttl=r["ttl"])
                for r in records if r.get("type") == QTYPE_A
            ]
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("A lookup failed for %s: %s", domain, exc)
            return []

    async def resolve_aaaa(self, domain: str) -> List[DNSRecord]:
        """Resolve AAAA (IPv6) records for a domain.

        Args:
            domain: Target domain.

        Returns:
            List of AAAA record results.
        """
        try:
            records = await self._query_udp_simple(domain, QTYPE_AAAA)
            return [
                DNSRecord(name=r["name"], type_name="AAAA", data=r["data"], ttl=r["ttl"])
                for r in records if r.get("type") == QTYPE_AAAA
            ]
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("AAAA lookup failed for %s: %s", domain, exc)
            return []

    async def resolve_mx(self, domain: str) -> List[DNSRecord]:
        """Resolve MX (mail exchange) records for a domain.

        Args:
            domain: Target domain.

        Returns:
            List of MX record results.
        """
        try:
            records = await self._query_udp_simple(domain, QTYPE_MX)
            return [
                DNSRecord(name=r["name"], type_name="MX", data=r["data"], ttl=r["ttl"])
                for r in records if r.get("type") == QTYPE_MX
            ]
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("MX lookup failed for %s: %s", domain, exc)
            return []

    async def resolve_txt(self, domain: str) -> List[DNSRecord]:
        """Resolve TXT records for a domain.

        Args:
            domain: Target domain.

        Returns:
            List of TXT record results.
        """
        try:
            records = await self._query_udp_simple(domain, QTYPE_TXT)
            return [
                DNSRecord(name=r["name"], type_name="TXT", data=r["data"], ttl=r["ttl"])
                for r in records if r.get("type") == QTYPE_TXT
            ]
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("TXT lookup failed for %s: %s", domain, exc)
            return []

    async def resolve_ns(self, domain: str) -> List[DNSRecord]:
        """Resolve NS (nameserver) records for a domain.

        Args:
            domain: Target domain.

        Returns:
            List of NS record results.
        """
        try:
            records = await self._query_udp_simple(domain, QTYPE_NS)
            return [
                DNSRecord(name=r["name"], type_name="NS", data=r["data"], ttl=r["ttl"])
                for r in records if r.get("type") == QTYPE_NS
            ]
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("NS lookup failed for %s: %s", domain, exc)
            return []

    async def enumerate_all(self, domain: str) -> DNSResult:
        """Run all standard DNS record lookups for a domain.

        Args:
            domain: Target domain.

        Returns:
            Aggregated DNSResult with all discovered records.
        """
        result = DNSResult(domain=domain)
        a, aaaa, mx, txt, ns = await asyncio.gather(
            self.resolve_a(domain),
            self.resolve_aaaa(domain),
            self.resolve_mx(domain),
            self.resolve_txt(domain),
            self.resolve_ns(domain),
            return_exceptions=True,
        )
        for r in a if isinstance(a, list) else []:
            result.records.append(r)
        for r in aaaa if isinstance(aaaa, list) else []:
            result.records.append(r)
        for r in mx if isinstance(mx, list) else []:
            result.records.append(r)
        for r in txt if isinstance(txt, list) else []:
            result.records.append(r)
        for r in ns if isinstance(ns, list) else []:
            result.records.append(r)

        return result

    async def attempt_axfr(self, domain: str, nameserver: Optional[str] = None) -> DNSResult:
        """Attempt a DNS zone transfer (AXFR) over TCP.

        Args:
            domain: Target domain.
            nameserver: Specific nameserver to query (uses domain's NS if None).

        Returns:
            DNSResult with AXFR records if successful.
        """
        result = DNSResult(domain=domain)
        ns_list = [nameserver] if nameserver else []

        if not ns_list:
            ns_records = await self.resolve_ns(domain)
            ns_list = [r.data for r in ns_records if r.data]

        for ns in ns_list:
            try:
                records = await self._axfr_query(domain, ns)
                if records:
                    result.axfr_supported = True
                    result.axfr_records = [
                        DNSRecord(name=r["name"], type_name=r["type_name"], data=r["data"], ttl=r["ttl"])
                        for r in records
                    ]
                    break
            except (OSError, asyncio.TimeoutError) as exc:
                logger.debug("AXFR failed for %s via %s: %s", domain, ns, exc)
                continue

        return result

    async def _axfr_query(self, domain: str, nameserver: str) -> List[Dict]:
        """Perform a single AXFR query over TCP.

        Args:
            domain: Target domain.
            nameserver: Nameserver IP to query.

        Returns:
            List of parsed resource records from the zone transfer.

        Raises:
            OSError: On connection or I/O errors.
            asyncio.TimeoutError: If connection times out.
        """
        def _do_axfr() -> List[Dict]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect((nameserver, DNS_PORT))
                packet = _build_dns_query(domain, QTYPE_AXFR)
                length = struct.pack(">H", len(packet))
                sock.sendall(length + packet)

                # Read 2-byte response length
                raw_len = sock.recv(2)
                if len(raw_len) < 2:
                    return []
                resp_len = struct.unpack(">H", raw_len)[0]

                # Read full response
                data = b""
                while len(data) < resp_len:
                    chunk = sock.recv(min(resp_len - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk

                return _parse_dns_response(data)
            finally:
                sock.close()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _do_axfr)

    async def subdomain_bruteforce(
        self, domain: str, wordlist_path: Optional[str] = None
    ) -> List[str]:
        """Brute-force subdomains using a wordlist.

        Uses ``ThreadPoolExecutor`` with configurable concurrency to
        resolve A records for candidate subdomains.

        Args:
            domain: Target domain.
            wordlist_path: Path to wordlist file (one subdomain per line).
                           Falls back to a minimal built-in list if None.

        Returns:
            Sorted list of resolved subdomain FQDNs.
        """
        subdomains: list[str] = []
        words: list[str] = []

        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
                    words = [line.strip() for line in f if line.strip()]
            except OSError as exc:
                logger.warning("Cannot read wordlist %s: %s", wordlist_path, exc)
                words = []

        if not words:
            words = [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1",
                "ns2", "smtp", "pop3", "imap", "admin", "cpanel", "whm",
                "ftp", "ssh", "vpn", "api", "dev", "test", "staging",
                "beta", "app", "portal", "mx", "exchange", "owa", "autodiscover",
                "m", "mobile", "status", "help", "support", "docs", "wiki",
                "git", "svn", "jenkins", "jira", "confluence", "gitlab",
                "kibana", "grafana", "prometheus", "monitor", "dashboard",
                "redis", "mysql", "db", "database", "mongo", "mongodb",
                "elastic", "elasticsearch", "kafka", "rabbitmq",
                "cdn", "static", "assets", "uploads", "download",
                "proxy", "gateway", "router", "fw", "firewall",
                "dc", "ad", "ldap", "radius", "nac",
                "cloud", "aws", "azure", "gcp", "s3",
                "backup", "mon", "nagios", "zabbix", "splunk",
                "jenkins", "nexus", "artifactory", "docker",
                "k8s", "kubernetes", "istio", "linkerd",
                "qa", "stage", "prod", "production", "development",
            ]

        found: list[str] = []
        lock = asyncio.Lock()

        async def _check(word: str) -> None:
            fqdn = f"{word}.{domain}"
            try:
                records = await self.resolve_a(fqdn)
                if records:
                    async with lock:
                        found.append(fqdn)
            except (OSError, asyncio.TimeoutError):
                pass

        sem = asyncio.Semaphore(self.config.concurrency)
        tasks: list[asyncio.Task] = []

        async def _bounded_check(word: str) -> None:
            async with sem:
                await _check(word)

        tasks = [asyncio.create_task(_bounded_check(w)) for w in words]
        await asyncio.gather(*tasks, return_exceptions=True)

        return sorted(found)

    async def run(self, domain: str) -> DNSResult:
        """Convenience: enumerate all records and optionally brute-force and AXFR.

        Args:
            domain: Target domain.

        Returns:
            Complete DNSResult with all discovered information.
        """
        result = await self.enumerate_all(domain)

        if self.config.axfr:
            axfr_result = await self.attempt_axfr(domain)
            result.axfr_supported = axfr_result.axfr_supported
            result.axfr_records = axfr_result.axfr_records

        if self.config.wordlist_path:
            result.subdomains = await self.subdomain_bruteforce(
                domain, self.config.wordlist_path
            )

        return result
