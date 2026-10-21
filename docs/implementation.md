# NetScope: Implementation Details

## 1. Module-by-Module Walkthrough

### Module A: Packet Ingestion (`capture/`)
- **`pcap_reader.py`**: Contains `OfflinePcapProcessor`. Uses Scapy's `PcapReader` to iterate through capture streams lazily. Enforces file existence, size checks, and clean stream closure inside a robust `finally` block to prevent file-locking conflicts on Windows.
- **`live_capture.py`**: Implements `LiveCaptureManager`. Manages a bounded FIFO queue (`queue.Queue(maxsize=5000)`). A dedicated sniffer thread runs Scapy's `sniff()`, pushing packets into the queue, while a consumer thread dispatches normalized parsing. Dropped frames resulting from queue overflow are counted via `queue_drops`.
- **`generate_samples.py`**: Generates deterministic synthetic PCAP files containing multi-protocol test traffic (ARP, DNS, HTTP, ICMP, IPv6, TLS, Fragments, SYN floods, Port scans).

### Module B: Parser & Classification (`analyzer/`)
- **`parser.py`**: Extracts fields across Link (Ethernet MAC, EtherType), Network (IPv4, IPv6, ARP), Transport (TCP, UDP, ICMP), and Application layers. Decodes TCP flags into human-readable tokens (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).
- **`protocol_classifier.py`**: Validates application protocols by examining packet payload bytes (HTTP request verbs, TLS record headers `0x16 0x03`, DNS query headers) rather than relying blindly on port numbers.
- **`flow_tracker.py`**: Tracks canonical 5-tuples `(min(ip1, ip2), max(ip1, ip2), proto, min(p1, p2), max(p1, p2))` to aggregate bidirectional conversations, forward/reverse volumes, inter-arrival durations, and TCP connection states (`SYN_SENT`, `SYN_ACK`, `ESTABLISHED`, `RESET`, `CLOSED`).

### Module C: Analytics Engine (`analytics/`)
- **`statistics.py`**: Implements `TrafficAnalytics`. Uses `collections.Counter` to maintain exact counters. Calculates:
  - Total packets and total counted bytes.
  - Average packet size: $\text{Avg Size} = \frac{\text{Total Bytes}}{\text{Total Packets}}$.
  - Duration: $\text{Duration} = \max(\text{Timestamp}) - \min(\text{Timestamp})$.
  - Capture PPS: $\text{Capture PPS} = \frac{\text{Total Packets}}{\text{Duration}}$.
  - Throughput: $\text{Throughput (bps)} = \frac{\text{Total Bytes} \times 8}{\text{Duration}}$.
  - Protocol share percentages per layer, guaranteed not to exceed 100%.
  - Chronological 1-second bucketing for timeline trend visualizations.

### Module D: Anomaly Detection (`analytics/`)
- **`anomaly_detector.py`**: Implements explainable, deterministic detection rules:
  1. *SYN Flood Detection*: Triggers when an IP sends $\ge 20$ standalone TCP SYN packets within 5 seconds without normal handshake completion.
  2. *Port Scan Detection*: Triggers when an IP queries $\ge 15$ distinct destination ports within a 5-second sliding window.
  3. *Packet Rate Spike*: Triggers when traffic exceeds 150 PPS in any timeline bucket.
  4. *Bandwidth Surge*: Triggers when throughput exceeds 500,000 bytes/sec (4 Mbps).
  5. *Dominant Host*: Triggers when a single IP accounts for $>50\%$ of all session traffic.
  - Implements a 10-second cooldown per alert key to prevent alert fatigue.

### Module E: Storage & Database (`storage/`)
- **`database.py`**: Implements `DatabaseManager`. Provides parameterized SQLite access with automated schema migrations. Tables include `sessions` (capture metadata), `session_summaries` (JSON analytical summaries), and `alerts` (security incident logs).

### Module F: REST API & Web Dashboard (`routes/`, `templates/`, `static/`)
- **`app.py`**: Flask application factory with error handlers, configuration loading, and localhost-only server binding.
- **`routes/api.py`**: Endpoints supporting server-side filtering, sorting, pagination, and RFC 4180 CSV export.
- **`templates/index.html`**: Clean dark navy dashboard with summary cards, protocol donut charts, traffic timeline, top talker tabs, and packet explorer grid.
- **`static/js/charts.js`**: Plotly.js charts rendered using bundled local script (`plotly.min.js`), requiring zero external internet connection.
- **`static/js/dashboard.js`**: Safe DOM construction using `textContent` for untrusted packet data, preventing XSS vulnerabilities.
