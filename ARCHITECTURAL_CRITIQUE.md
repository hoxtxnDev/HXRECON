# Architectural Self-Critique — HXRECON v1.0.0

## Weakness 1: Pure-Async TCP Connect Scan Reliability

**Current limitation:** The TCP scanner in `modules/scanner.py` relies
entirely on `asyncio.open_connection()` to determine port state. On
modern networks with stateful firewalls, a TCP SYN to a filtered port
may simply drop the packet (no RST, no ICMP unreachable), causing the
scanner to wait the full timeout duration before classifying the port
as "filtered." When scanning 65,535 ports with a 3-second timeout, this
creates a worst-case runtime of ~196,000 seconds (54+ hours) for a
full-range scan, even with 500 concurrent tasks.

**Why it matters in a real engagement:** Red teams typically have a
limited time window. Spending hours waiting for timeouts on filtered
ports wastes the engagement window. Professional scanners (masscan,
nmap) use raw SYN packets with custom retransmission timers to
dramatically reduce scan time on filtered networks.

**V2 engineering solution:** Implement a raw-socket fallback using
`ctypes` + `PF_PACKET` (Linux) or `ws2_32.dll` (Windows) to send
custom TCP SYN packets and parse RST/SYN-ACK responses. This would:
- Eliminate per-port timeout on filtered ports (single RTT to classify
  connection refused vs. filtered)
- Allow configurable retransmission with exponential backoff
- Enable TCP window size fingerprinting for OS detection

Implementation hint: Use `socket.socket(socket.AF_INET, socket.SOCK_RAW,
socket.IPPROTO_TCP)` with `IP_HDRINCL` on Linux. Build the IP + TCP
header manually via `struct.pack`. Parse the response with a raw socket
receive loop. This requires root/Administrator privileges and is
platform-specific.

---

## Weakness 2: Single-Threaded Event Loop Bottleneck on Large Subdomain Wordlists

**Current limitation:** The DNS subdomain brute-force in
`modules/dns_recon.py` uses an `asyncio.Semaphore` + per-subdomain
coroutine approach for concurrent queries. Each coroutine constructs a
raw DNS packet, opens a UDP socket via `loop.run_in_executor`, sends the
query, and parses the response. For wordlists exceeding 100,000 entries
(e.g., `subdomain_big.txt` from SecLists), the overhead of creating
100,000 asyncio tasks and managing the executor thread pool becomes a
significant bottleneck — task creation alone can take 5-10 seconds, and
the GIL contention during DNS response parsing reduces throughput.

**Why it matters in a real engagement:** Large subdomain bruteforcing
is a standard red team technique for discovering external attack surface.
Missing a subdomain like `vpn.target.com` or `jenkins.internal.target.com`
can mean missing the critical foothold vector. Slow brute-force limits
the depth of enumeration possible within an engagement window.

**V2 engineering solution:** Replace the per-domain asyncio task model
with a connection-pooled UDP multiplexer:
- Pre-allocate a fixed pool of raw UDP sockets (e.g., 100 sockets bound
  to different ephemeral ports)
- Use `socketserver.ThreadingUDPServer` or a custom asyncio datagram
  endpoint with a single recv loop
- Maintain a dict mapping DNS transaction IDs → pending futures
- Send queries in batches, read responses in a single recv loop, and
  dispatch results to futures by matching transaction IDs

This reduces the per-query overhead from ~100 μs (task creation) to
~1 μs (dict insert + socket sendto). Implementation hint: Use a shared
`asyncio.DatagramProtocol` with a dict of `{tid: asyncio.Future}` and
call `protocol.sendto()` directly without creating per-query transports.

---

## Weakness 3: No SYN Stealth Scan Capability

**Current limitation:** The scanner implements only TCP connect scanning
(`connect()` syscall completes the full three-way handshake). This is the
most detectable scan type — every target system logs a completed TCP
connection in `auth.log`, `syslog`, or Windows Event Log (Event ID 5154).
Additionally, application-layer services (SSH, HTTP) will log the
connection attempt at the application level, providing the target's
blue team with a clear audit trail.

**Why it matters in a real engagement:** TCP connect scanning guarantees
detection. Red teams performing covert reconnaissance require stealth —
they need to identify open ports without completing the TCP handshake
or triggering application-layer logging. A SYN scan (half-open scan)
sends only the SYN packet and responds with RST upon receiving SYN-ACK,
never completing the connection. This bypasses most application-layer
logging and many host-based IDS sensors.

**V2 engineering solution:** Implement a raw-socket SYN scanner as a
drop-in replacement for the TCP connect scanner:
- Construct raw IP + TCP packets with the SYN flag set
- Send via `socket.SOCK_RAW` with `IPPROTO_TCP`
- Listen for SYN-ACK (open) or RST (closed) responses
- Respond to SYN-ACK with a RST packet to prevent connection completion
- Track outstanding probes using a dict of `{target_ip:port: seq_num}`
- Use `select.epoll()` (Linux) or `select.poll()` for high-performance
  response multiplexing

This requires CAP_NET_RAW or root. Fall back gracefully to TCP connect
when raw sockets are unavailable (document this in the code, log the
capability level at startup). Implementation hint: Build the TCP pseudo
header checksum carefully — this is the most common source of "SYN packets
arrive but get no response" bugs. Use Wireshark during development to
validate checksums.
