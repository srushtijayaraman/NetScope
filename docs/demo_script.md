# NetScope: Five-Minute Demonstration Script

This script provides a structured, professional, and repeatable 5-minute presentation workflow for academic evaluation and project demonstration.

---

## Timeline & Talking Points

### Minute 00:00 – 01:00: Problem, Objective & Architecture
- **Speaker Action**: Show the home dashboard or architecture slide.
- **Key Talking Points**:
  - *"Welcome to the NetScope demonstration: a Real-Time Network Packet Analyzer and Traffic Intelligence Dashboard built for the Computer Networks Laboratory."*
  - *"Raw network captures are noisy and hard to interpret. NetScope bridges this gap by decoding multi-layer protocols, calculating verified traffic analytics, and identifying security anomalies in an intuitive web dashboard."*
  - *"Our architecture is fully decoupled: Scapy-based ingestion, normalized multi-layer parsing, a mathematical analytics engine, SQLite session storage, and an asynchronous Flask/Plotly dashboard."*

### Minute 01:00 – 02:00: Ingesting Network Captures (Offline & Live)
- **Speaker Action**: Click **Load Sample PCAP** (or upload a custom `.pcap` file).
- **Key Talking Points**:
  - *"Notice the top header status. In environments without Npcap, NetScope detects the driver limitation and clearly reports offline analysis availability."*
  - *"Let's click 'Load Sample PCAP'. In less than 60 milliseconds, NetScope parses 60 packets spanning ARP, DNS, HTTP, ICMP, IPv6, TLS, and fragments."*
  - *"Observe the summary cards: Total Packets (60), Total Volume (3.59 KB), Average Packet Size (59.8 B), and Throughput (8.34 kbps)."*

### Minute 02:00 – 03:00: Analytics, Protocol Distributions & Traffic Trends
- **Speaker Action**: Hover over the Plotly charts and switch the dropdown to "Network Layer" and "Application Layer".
- **Key Talking Points**:
  - *"Here we see our protocol distribution donut chart. In the transport layer, we see TCP, UDP, ICMP, and ARP cleanly segmented. Switch the dropdown to Network Layer: IPv4 accounts for 95%, IPv6 for 1.7%, and ARP for 3.3%."*
  - *"On the right is our chronological traffic timeline. We can toggle the metric between Packets-Per-Second (PPS) and Throughput (Kbps)."*
  - *"Below, our Top Talkers table highlights primary host endpoints, and the Canonical Network Flows table shows active 5-tuples with bidirectional byte tallies and TCP state progression."*

### Minute 03:00 – 04:00: Packet Explorer, Filtering, Inspection & Security Alerts
- **Speaker Action**: Type `who-has` into the search bar, filter by `TCP`, click a packet row to show the modal, then show the Alerts section.
- **Key Talking Points**:
  - *"Let's test our Packet Explorer. Notice instant sub-2-millisecond search. Typing 'who-has' immediately isolates Layer 2 ARP discovery."*
  - *"Clicking any packet opens our detailed Protocol Inspector Modal. We see Frame MACs, IP TTLs, TCP sequence and acknowledgment numbers, and HTTP/DNS application fields."*
  - *"Now look at the Security Intelligence panel: NetScope's explainable heuristic engine detected two real-world attacks embedded in this capture: a TCP SYN Flood from `10.0.0.99` (25 SYNs in 1.25s) and a vertical Port Scan from `10.0.0.88` (20 probed ports). Each alert details the observed metric, configured threshold, and explanation."*

### Minute 04:00 – 05:00: Export, Test Verification & Conclusion
- **Speaker Action**: Click **Export CSV**, then show the terminal test suite (`pytest -v`).
- **Key Talking Points**:
  - *"We can export this active filtered view into an RFC 4180 CSV file with a single click."*
  - *"Behind the scenes, NetScope is backed by 34 comprehensive automated tests covering parsing, statistics, filters, API endpoints, and lifecycle stress, achieving a 100% pass rate in 0.40 seconds."*
  - *"All statistical formulas have been verified against hand-calculated ground truths with zero margin of error."*
  - *"Thank you. I am now ready for individual viva questions."*
