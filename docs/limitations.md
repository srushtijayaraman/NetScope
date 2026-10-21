# NetScope: Operational Limitations & System Constraints

## 1. Operating System & Live Capture Drivers
- **Windows Npcap Dependency**: Live packet sniffing on Windows requires Npcap (or WinPcap) with "WinPcap API-compatible mode" enabled to inject and capture raw Ethernet frames. On systems where Npcap is not installed, live capture is safely reported as `UNSUPPORTED_BACKEND`, while offline PCAP analysis remains 100% operational.
- **Linux/POSIX Raw Socket Permissions**: On Linux systems, live sniffing requires `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities or superuser privilege (`sudo`).

## 2. Cryptographic Encryption & Payload Visibility
- **Encrypted TLS Traffic**: NetScope observes and classifies TLS traffic (inspecting TLS Record layer versions, Client Hello / Server Hello handshakes, and port 443 contexts). It **does not** decrypt encrypted application records, as doing so without private key material would compromise cryptographic confidentiality.
- **Payload Privacy**: In compliance with academic ethics and data protection principles, raw payload hexadecimal bytes are neither displayed in the UI nor written to disk by default.

## 3. IP Fragmentation & Reassembly Limits
- **Fragment Flagging**: NetScope detects IPv4 fragmentation (`flags: MF` or `fragment_offset > 0`) and tags individual fragments with their offset values.
- **Reassembly Bounds**: Stateful fragment reassembly across high-throughput lossy channels is deliberately omitted to prevent reassembly buffer exhaustion and Denial-of-Service attacks against the analyzer.

## 4. Port-Based Application Inference Caveats
- Standard ports (e.g. 80, 443, 53) provide contextual hints, but NetScope avoids asserting application protocols with absolute certainty unless verifiable payload signatures (HTTP methods/status lines, DNS query records, TLS handshake byte sequences) are decoded. Unidentified payloads on standard ports are flagged as `Inferred` or `Unknown`.

## 5. In-Memory Retention & Scalability Boundaries
- While `TrafficAnalytics` aggregates millions of packets with flat $O(1)$ memory complexity, the detailed packet explorer retains up to `MAX_MEMORY_PACKETS = 10,000` records in an in-memory buffer to prevent browser DOM and host memory crashes during multi-gigabyte PCAP processing.
