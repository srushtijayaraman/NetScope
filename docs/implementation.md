# NetScope: Implementation Details

## 1. Module-by-Module Walkthrough

### Module A: Packet Ingestion (`capture/`)
- **`pcap_reader.py`**: Contains `OfflinePcapProcessor`. Uses Scapy's `PcapReader` to iterate through capture streams lazily. Enforces file existence, size checks, relative timestamp computation starting from `t0 = 0.000s`, and clean stream closure inside a robust `finally` block to prevent file-locking conflicts on Windows.
- **`live_capture.py`**: Implements `LiveCaptureManager`. Manages a bounded FIFO queue (`queue.Queue(maxsize=5000)`). A dedicated sniffer thread runs Scapy's `sniff()`, pushing packets into the queue, while a consumer thread dispatches normalized parsing. Dropped frames resulting from queue overflow are accounted for via `queue_drops`. Missing capture drivers (Npcap on Windows) are detected and surfaced with remediation instructions without crashing.
- **`generate_samples.py`**: Generates deterministic synthetic PCAP files containing multi-protocol test traffic (ARP, DNS, HTTP, ICMP, IPv6, TLS, Fragments, SYN floods, Port scans).

### Module B: Parser & Classification (`analyzer/`)
- **`parser.py`**: Extracts fields across Link (Ethernet MAC, EtherType), Network (IPv4, IPv6, ARP), Transport (TCP, UDP, ICMP), and Application layers.
  - Decodes TCP flags into human-readable tokens (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`).
  - Implements deep DNS decoding: Transaction ID, query names, query type names (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`, `NS`, `SOA`), flags (`AA`, `TC`, `RD`, `RA`), response codes (`NOERROR`, `NXDOMAIN`, `SERVFAIL`), and decoded answer records.
  - Computes per-packet relative timestamp (`relative_time_sec`).
  - Guarantees defensive parsing: any unhandled exception or corrupted raw payload returns `parsing_status = "Malformed"` with diagnostic error details instead of crashing the process.
- **`protocol_classifier.py`**: Validates application protocols by examining packet payload bytes (HTTP request verbs, TLS record headers `0x16 0x03`, DNS query headers) rather than relying blindly on port numbers.
- **`flow_tracker.py`**: Tracks canonical 5-tuples `(min(ip1, ip2), max(ip1, ip2), proto, min(p1, p2), max(p1, p2))` to aggregate bidirectional conversations, forward/reverse volumes, inter-arrival durations, packet reference lists, and TCP connection states (`SYN_SENT`, `SYN_ACK`, `ESTABLISHED`, `RESET`, `CLOSING`, `CLOSED`). Injects a unique `flow_id` (`flow-1`, `flow-2`, ...) into each packet record.

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
- **`anomaly_detector.py`**: Implements explainable, configurable detection rules distinguishing observable facts from heuristic suspicions:
  1. *SYN Burst Suspicion (Possible SYN Flood)*: Triggers when an IP sends $\ge 20$ standalone TCP SYN packets within 5 seconds without normal handshake completion. Attaches supporting packet ID references.
  2. *Multi-Port Query Pattern (Possible Port Scan)*: Triggers when an IP queries $\ge 15$ distinct destination ports within a 5-second sliding window. Differentiates single-host vertical probes from distributed horizontal scans.
  3. *Volumetric Packet Rate Spike*: Evaluates observed packet arrival rate exceeding threshold (default: 150 PPS).
  4. *Bandwidth Surge*: Evaluates byte rate exceeding threshold (default: 500,000 bytes/sec).
  5. *Dominant Host Volume*: Flags when a single IP accounts for $>50\%$ of all session traffic.
  - Supports runtime threshold reconfiguration via `GET/POST /api/alerts/config`.
  - Implements a 10-second cooldown per alert key to prevent alert fatigue.

### Module E: Storage & Database (`storage/`)
- **`database.py`**: Implements `DatabaseManager`. Provides parameterized SQLite access with automated schema migrations. Tables include `sessions` (capture metadata), `session_summaries` (JSON analytical summaries), and `alerts` (security incident logs).

### Module F: REST API & Web Dashboard (`routes/`, `templates/`, `static/`)
- **`app.py`**: Flask application factory with error handlers, configuration loading, and localhost-only server binding (`127.0.0.1:5000`).
- **`routes/api.py`**: Endpoints supporting server-side filtering (protocol, IPs, ports, packet ID, flow ID, text search), sorting, pagination, active flow retrieval (`/api/flows`), threshold configuration (`/api/alerts/config`), and RFC 4180 CSV export.
- **`templates/index.html`**: Clean dark navy dashboard with summary cards, protocol donut charts, traffic timeline, top talker tabs, flow filter badges, active flow inspection, threshold tuning modal, loading overlay, and packet explorer grid.
- **`static/js/charts.js`**: Plotly.js charts rendered using bundled local script (`plotly.min.js`), requiring zero external internet connection.
- **`static/js/dashboard.js`**: Safe DOM construction using `textContent` for untrusted packet data, preventing XSS vulnerabilities. Implements one-click alert packet drilldown and conversation flow filtering.
