# NetScope: Comprehensive Viva Examination Preparation

This document contains 28 academic viva voce questions and in-depth technical answers tailored directly to the implemented NetScope codebase and computer networking fundamentals.

---

### Category 1: Networking Fundamentals & Layering
#### Q1: What is the OSI 7-Layer model and how does NetScope map to it?
**Answer**: The OSI model categorizes networking into 7 abstraction layers: Physical, Data Link, Network, Transport, Session, Presentation, Application. NetScope captures Layer 2 frames (Ethernet MAC, ARP), decodes Layer 3 (IPv4/IPv6), inspects Layer 4 (TCP, UDP, ICMP), and extracts recognized Layer 7 protocols (DNS, HTTP, TLS). It maps these into structured dictionary representations (`link_layer`, `network_layer`, `transport_layer`, `application_layer`).

#### Q2: What is the difference between an Ethernet MAC address and an IP address?
**Answer**: An Ethernet MAC address is a 48-bit hardware identifier burned into the Network Interface Card (NIC), used for hop-by-hop local frame delivery at Layer 2 within a broadcast domain. An IP address (32-bit IPv4 or 128-bit IPv6) is a logical network-layer address used for end-to-end routing across heterogeneous interconnected networks.

#### Q3: How does ARP (Address Resolution Protocol) work, and how does NetScope decode it?
**Answer**: ARP maps a known Layer 3 IP address to an unknown Layer 2 MAC address. The requester broadcasts an ARP request (`op=1`, "who-has IP tell my MAC"). The target host replies with a unicast ARP response (`op=2`, "is-at target MAC"). In `analyzer/parser.py`, NetScope parses `psrc`, `pdst`, `hwsrc`, `hwdst`, and `op`, classifying it with `network_protocol="ARP"` and `transport_protocol="None"`.

---

### Category 2: Network & Transport Layer Protocols
#### Q4: Explain the TCP 3-Way Handshake and how NetScope tracks it.
**Answer**: A TCP connection begins with:
1. Client sends `SYN` (Synchronize, with initial sequence number).
2. Server responds with `SYN-ACK` (Synchronize and Acknowledge).
3. Client sends `ACK` (Acknowledge).
NetScope's `FlowTracker` maintains canonical 5-tuples. Upon observing a `SYN`, it sets connection state to `SYN_SENT`; upon `SYN+ACK`, to `SYN_ACK`; and upon `ACK`, transitions to `ESTABLISHED`. If a `RST` flag is observed, the state transitions to `RESET`.

#### Q5: How do TCP and UDP differ in design, header size, and delivery guarantees?
**Answer**: TCP is a connection-oriented, reliable protocol providing flow control (sliding window), error recovery, sequence ordering, and congestion control, with a minimum 20-byte header. UDP is connectionless, unreliable, and message-oriented with an 8-byte header (`sport`, `dport`, `len`, `chksum`), prioritizing low latency over delivery guarantees.

#### Q6: How does NetScope decode TCP flags from raw bytes?
**Answer**: In `analyzer/parser.py`, `parse_tcp_flags(flags_val)` performs bitwise AND operations against standard TCP flag bitmasks: `FIN` (0x01), `SYN` (0x02), `RST` (0x04), `PSH` (0x08), `ACK` (0x10), `URG` (0x20), `ECE` (0x40), `CWR` (0x80). If Scapy passes string representation, a character mapping fallback extracts the flags.

#### Q7: What is ICMP and why is it categorized as transport in NetScope?
**Answer**: The Internet Control Message Protocol (ICMP) is technically a network-layer control mechanism that rides directly inside IP packets (IP protocol number 1). In NetScope, it is categorized alongside TCP and UDP in the transport visualization layer because it operates as a distinct L4 payload carrying Type and Code numbers (e.g., Type 8 Echo Request, Type 0 Echo Reply, Type 3 Destination Unreachable).

---

### Category 3: Application Layer Protocols
#### Q8: How does DNS work, and what fields does NetScope extract?
**Answer**: The Domain Name System (DNS) translates human-readable domain names (e.g. `example.com`) to IP addresses, typically over UDP port 53. NetScope decodes the query/response flag (`qr`), question name (`qd.qname`), query type (`qtype`), response code (`rcode`), and answer resource records (`an`), displaying the resolved IP addresses in the packet detail modal.

#### Q9: Can NetScope decrypt HTTPS / TLS traffic? Why or why not?
**Answer**: No. TLS (Transport Layer Security) uses asymmetric cryptography for authentication/key exchange and symmetric ciphers (e.g., AES-GCM) with ephemeral session keys for payload encryption. Without the client's session secrets or private server key, decrypting TLS payload is computationally infeasible. NetScope inspects only plaintext TLS record headers (`0x16 0x03`) and handshake metadata.

#### Q10: Why does NetScope not rely solely on standard port numbers to identify application protocols?
**Answer**: Attackers and custom applications frequently run non-standard protocols on standard ports (e.g., SSH or malware tunnels over port 80/443), or standard protocols on unusual ports (e.g., HTTP on 8080/8000). Relying on ports alone produces false positives. NetScope verifies actual byte signatures (HTTP verbs, TLS record byte sequences) before asserting application classification.

---

### Category 4: Packet Ingestion, Queues & Concurrency
#### Q11: How does Scapy read PCAP files offline without WinPcap/Npcap?
**Answer**: PCAP files have a standardized binary file format (a 24-byte global header followed by packet headers containing timestamps, wire length, and captured length). Scapy's `PcapReader` reads these byte streams directly in Python using standard file I/O (`open()`) and unpacks packet bytes without needing a low-level network packet capture driver.

#### Q12: Why is a bounded queue necessary in the live capture subsystem?
**Answer**: In high-throughput live capture, incoming packet arrival can exceed the speed at which parsing, database writes, and UI updates execute. If processing is synchronous in the packet callback, frames are dropped by the OS buffer. NetScope uses a separate background sniffer thread and bounded FIFO queue (`queue.Queue(maxsize=5000)`). If the queue fills up, incoming packets are dropped cleanly with `queue_drops` incremented, preventing memory exhaustion.

#### Q13: What happens on Windows if Npcap is not installed?
**Answer**: Windows does not provide raw Layer 2 packet access natively. Without Npcap, Scapy cannot attach to network adapters or open promiscuous sockets. In NetScope, `check_live_capture_capability()` detects this condition, transitions the status to `UNSUPPORTED_BACKEND`, informs the user, and keeps all offline PCAP analysis features 100% operational.

---

### Category 5: Mathematical Formulas & Traffic Analytics
#### Q14: How is network throughput calculated, and what is the difference between bps and Bps?
**Answer**: Throughput measures data transmission rate over time:
$$\text{Throughput (bps)} = \frac{\text{Total Bytes Counted} \times 8}{\text{Capture Duration (seconds)}}$$
$\text{Bps}$ represents Bytes per second, whereas $\text{bps}$ represents bits per second ($1 \text{ Byte} = 8 \text{ bits}$). NetScope displays throughput in $\text{bps}$, $\text{kbps}$ ($\times 10^{-3}$), and $\text{Mbps}$ ($\times 10^{-6}$).

#### Q15: What is the difference between Capture Duration and Processing Duration?
**Answer**: Capture Duration is the actual network time elapsed between the first and last packet recorded in the capture ($\max(t) - \min(t)$). Processing Duration is the CPU wall-clock time required by Python to read, parse, and analyze those packets. For example, a 60-packet capture spanning 3.44 seconds of network time was processed by NetScope in 0.0317 seconds of wall-clock time.

#### Q16: How does NetScope prevent zero-division errors in its analytics formulas?
**Answer**: In `analytics/statistics.py`, defensive guards check if `total_packets == 0` or `duration <= 0.0`. If a capture contains only one packet or zero duration, `get_capture_pps()` and `get_throughput()` safely return 0.0 or the immediate packet count rather than raising `ZeroDivisionError`.

#### Q17: How is Average Packet Size defined?
**Answer**: $\text{Avg Packet Size} = \frac{\sum_{i=1}^N \text{len}_i}{N}$. In NetScope, it sums the wire length of all accepted packets and divides by the total packet count, rounded to two decimal places.

---

### Category 6: Anomaly Detection & Security Intelligence
#### Q18: What is a TCP SYN Flood, and how does NetScope detect it?
**Answer**: A SYN flood is a Denial-of-Service attack where an attacker sends a flood of TCP `SYN` packets to exhaust the victim's server state table (SYN queue). The server allocates resources for half-open connections that never complete. NetScope's `AnomalyDetector` tracks SYN timestamps per source IP in a 5-second sliding window. If an IP sends $\ge 20$ SYNs without matching ACKs, a `HIGH` severity alert is fired.

#### Q19: What is a Port Scan and how does NetScope detect it?
**Answer**: A port scan is a reconnaissance technique where an attacker probes multiple ports on a target host to identify active services and open listening sockets. NetScope maintains a sliding deque of `(timestamp, destination_port)` per source IP. If $\ge 15$ distinct ports are probed within 5 seconds, a `Port Scan Detected` alert is fired.

#### Q20: What is alert cooldown and why is it critical?
**Answer**: If a rule fires on every offending packet, a 10,000-packet SYN flood would generate 10,000 identical alert records, overwhelming the database and user interface. NetScope enforces a configurable cooldown window (`ANOMALY_COOLDOWN_SECONDS = 10`), ensuring at most one alert per `(alert_type, target)` pair every 10 seconds.

---

### Category 7: Software Engineering, Architecture & Testing
#### Q21: Why was Flask chosen over larger frameworks like Django?
**Answer**: NetScope requires a lightweight, fast, local REST API service without the heavy overhead of ORM migrations, administrative panels, or complex middleware. Flask provides minimal footprint, rapid startup, straightforward blueprint routing, and clean integration with Scapy and SQLite.

#### Q22: How does NetScope protect against Cross-Site Scripting (XSS)?
**Answer**: Packet payloads and header summaries can contain arbitrary, potentially hostile strings (e.g. malformed HTTP User-Agents or DNS names). NetScope's frontend code in `static/js/dashboard.js` uses `textContent` and safe DOM node creation methods rather than vulnerable `innerHTML` concatenation for packet values.

#### Q23: Why is SQLite suitable for this project, and how are SQL injection attacks prevented?
**Answer**: SQLite requires zero server daemon setup, stores sessions in a single file (`storage/netscope.db`), and provides ACID guarantees. All database queries in `storage/database.py` use parameterized queries with `?` placeholders, completely preventing SQL injection vulnerabilities.

#### Q24: What is the purpose of synthetic fixtures in `tests/conftest.py`?
**Answer**: Synthetic fixtures create deterministic, mathematically exact packet objects (fixed MACs, IPs, ports, sequence numbers, and timestamps). This allows unit and regression tests to execute reliably across any operating system without depending on live network connectivity or fluctuating traffic.

---

### Category 8: Wireshark & Industrial Verification
#### Q25: How do NetScope's metrics compare with Wireshark?
**Answer**: Wireshark is the gold-standard packet dissection engine written in C/C++ using `libpcap`/`Npcap`. NetScope achieves identical counts for packet numbers, byte sums, IP addresses, port numbers, TCP sequence numbers, and flags on identical PCAP files. Wireshark performs deeper dissection into proprietary sub-protocols, whereas NetScope focuses on real-time traffic statistics, aggregation, and web accessibility.

#### Q26: What is the difference between packet length and captured length?
**Answer**: Packet length (wire length) is the original length of the frame transmitted on the physical wire. Captured length (snaplen) is the number of bytes actually saved to the PCAP file. If a capture used a snapshot length of 64 bytes, captured length is 64 even if the wire length was 1514 bytes.

#### Q27: What is an IP Fragment, and how does Wireshark/NetScope represent it?
**Answer**: If an IP packet exceeds the Maximum Transmission Unit (MTU) of a link (typically 1500 bytes for Ethernet), the router or sender fragments it into multiple smaller IP packets. Each fragment shares the same IP `Identification`, has `flags: MF` (More Fragments) set (except the last), and includes a non-zero `Fragment Offset` (in 8-byte units). NetScope tags these as `parsing_status: "Fragment"` and decodes the offset.

#### Q28: How does NetScope prevent unbounded memory growth during continuous capture?
**Answer**: NetScope employs a two-tier storage model:
1. `TrafficAnalytics` aggregates counters in constant $O(1)$ memory.
2. The packet explorer maintains a ring buffer capped at `MAX_MEMORY_PACKETS = 10,000` items.
3. Persistent session summaries and alerts are saved to SQLite on disk, preserving host stability.
