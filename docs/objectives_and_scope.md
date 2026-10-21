# NetScope: Objectives and Scope

## 1. Concrete Objectives
The primary objective of NetScope is to construct a production-quality, academically defensible network packet analyzer and traffic intelligence dashboard within a strict two-day deadline.

### Specific Engineering Objectives:
1. **Incremental PCAP Ingestion**: Ingest standard PCAP/PCAPNG files incrementally using Python and Scapy without exhausting host memory.
2. **Normalized Multi-Layer Protocol Parsing**: Extract normalized representations of Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS packets.
3. **Deterministic Traffic Analytics**: Calculate total packet count, byte volume, average packet size, capture duration, packets-per-second (PPS), and bandwidth throughput (bps/kbps/Mbps).
4. **Interactive Dashboard**: Deliver a responsive, dark-mode web dashboard featuring Plotly.js charts, an interactive packet explorer with pagination and search, and deep-dive packet inspection.
5. **Flow State Tracking**: Maintain symmetric canonical 5-tuples `(IP A, IP B, Protocol, Port A, Port B)` with bidirectional packet and volume metrics and TCP connection lifecycle states.
6. **Explainable Anomaly Alerts**: Implement deterministic heuristics for TCP SYN floods, horizontal/vertical port scans, packet rate spikes, and bandwidth surges.
7. **Filterable CSV Export**: Enable users to stream filtered packet records into CSV format for offline reporting.
8. **Automated Testing Suite**: Maintain >95% test pass rate across unit, integration, and lifecycle test suites with synthetic fixtures.

## 2. In-Scope Functionality
- **File Formats**: `.pcap`, `.pcapng`, `.cap`.
- **Supported Link Layer**: Ethernet II (MAC addresses, EtherType).
- **Supported Network Layer**: IPv4 (TTL, ID, fragment offset, flags, checksum), IPv6 (Traffic Class, Flow Label, Hop Limit), ARP (Who-has, Is-at).
- **Supported Transport Layer**: TCP (ports, seq, ack, flags, window, checksum), UDP (ports, length, checksum), ICMP/ICMPv6 (Type, Code, ID, Seq).
- **Supported Application Layer**: DNS (Queries, Responses, RCODE, Answers), HTTP (Method, URI, Status Line), TLS (Client/Server Handshake record identification).
- **Live Capture Architecture**: Scapy background worker with bounded queue, drop accounting, and driver diagnostics.
- **Persistence**: SQLite metadata storage for sessions, statistics summaries, and alerts.

## 3. Out-of-Scope (Limitations & Non-Goals)
- **Payload Decryption**: NetScope does not decrypt encrypted TLS payloads; it strictly inspects unencrypted TLS record headers and SNI/version metadata.
- **Deep Packet Inspection (DPI) Reassembly**: Fragment reassembly is flagged (`Fragment`), but reassembly buffers are bounded to avoid kernel memory exhaustion.
- **Offensive Actions**: NetScope is purely an observational diagnostic platform; it does not block packets, inject reset frames, or execute active network countermeasures.
- **Public Cloud Dependencies**: Runs 100% locally on localhost without requiring internet access, Redis, Docker, or external CDNs.
