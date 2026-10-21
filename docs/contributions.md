# NetScope: Team Contribution Record

This document provides a transparent template for attributing individual contributions in accordance with academic integrity guidelines.

---

## Individual Contribution Breakdown

| Team Member Name | Student ID / Roll No. | Subsystem Responsibilities | Key Modules Authored | Signed / Verified |
|---|---|---|---|---|
| *[Member 1]* | *[Roll No.]* | Ingestion & Architecture | `capture/pcap_reader.py`, `capture/live_capture.py` | [ ] |
| *[Member 2]* | *[Roll No.]* | Protocol Parsing & Decoding | `analyzer/parser.py`, `analyzer/protocol_classifier.py` | [ ] |
| *[Member 3]* | *[Roll No.]* | Traffic Analytics & Heuristics | `analytics/statistics.py`, `analytics/anomaly_detector.py` | [ ] |
| *[Member 4]* | *[Roll No.]* | Dashboard UI & Visualization | `templates/index.html`, `static/js/`, `routes/api.py` | [ ] |
| *[Member 5]* | *[Roll No.]* | Quality Assurance & Testing | `tests/`, `benchmark_experiments.py`, Docs | [ ] |

---

## Detailed Task Matrix

- **Packet Ingestion & Capture Engine**:
  - Offline incremental PCAP/PCAPNG ingestion.
  - Asynchronous live sniffing thread and bounded FIFO queue overflow handling.
- **Protocol Dissection & Decoding**:
  - Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS decoding.
  - Multi-fragment identification and defensive field handling.
- **Mathematical Analytics & Statistical Modeling**:
  - Throughput calculations (bps/kbps/Mbps), capture rate (PPS), average packet size, and duration.
  - Donut distribution algorithms and chronological time-bucketing.
- **Security & Anomaly Intelligence**:
  - Heuristic detection rules for TCP SYN Floods, Port Scanning, and Dominant Traffic Hosts.
  - Cooldown deduplication and explainable alert evidence structures.
- **Interactive Web Interface & REST API**:
  - Dark-mode responsive UI with Plotly.js charts and instant search filtering.
  - RFC 4180 CSV export stream and packet detail inspection modal.
- **Quality Assurance & Verification**:
  - Comprehensive automated pytest test suite (34 passing test cases).
  - Industrial Wireshark verification methodology and benchmark performance experiments.
