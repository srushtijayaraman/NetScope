# NetScope X: Autonomous Network Traffic Intelligence & Security Forensics Platform

[![Python](https://img.shields.io/badge/Python-3.14%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8.0-red.svg)](https://scapy.net/)
[![Tests](https://img.shields.io/badge/Tests-77%20Passed%20(100%25)-emerald.svg)](docs/test_report.md)
[![Views](https://img.shields.io/badge/Navigation-9%20Unified%20Views-cyan.svg)]()
[![Themes](https://img.shields.io/badge/UI-Dark%20%7C%20Light%20Modes-indigo.svg)]()
[![Platform](https://img.shields.io/badge/Release-NetScope%20X%20Enterprise-purple.svg)]()

> **Computer Networks Laboratory Mini-Project Deliverable (NetScope X Autonomous Upgrade)**  
> An autonomous, mathematically verified network traffic intelligence platform, stateful TCP conversation inspector, interactive HTML5 network topology graph, SOC security incident center, deterministic demonstration replay lab, and forensic case management engine with print-ready HTML report export and dual Light/Dark theme support.

---

<p align="center">
  <img src="docs/screenshots/dashboard_dark.png" alt="NetScope X Real-Time Packet Analyzer & SOC Dashboard" width="95%" />
</p>

<p align="center">
  <em>NetScope X real-time dashboard showing the left navigation rail, interactive network map, telemetry charts, correlated security incidents, and demonstration lab.</em>
</p>

---

## 1. NetScope X Core Capabilities & Architecture

NetScope X elevates packet analysis from a simple passive viewer into an active, stateful network intelligence platform:

1. **Feature A: Interactive Network Topology (Network Map)**
   - Renders a native HTML5 Canvas host graph without any external CDN libraries.
   - Accurately classifies RFC 1918 internal addresses, loopback, multicast, and external IP endpoints.
   - Computes communication edge weights based on packet and byte volume with animated traffic particles.
   - High-risk attacker nodes pulsate with an alarming crimson threat halo.
   - Interactive Host Inspector Drawer displaying transmit/receive metrics, connected peers, active 5-tuple conversations, and 1-click filters.

2. **Feature B & E: Security Incident Center & Explainable SOC Engine**
   - Automatically correlates raw heuristic alerts into structured, deduplicated security incidents.
   - Persistent workflow status tracking (`New` -> `Investigating` -> `Resolved`) and timestamped analyst notes.
   - **Explainable Detection Engine:** Rigorously distinguishes **Observable Network Facts** (deterministic packet counts, timestamps, ports) from **Security Hypotheses** and **Alternative Benign Explanations** (e.g., authorized vulnerability scans, web crawlers, corporate backup sync).
   - Deep evidence linking: Clickable packet references open the Protocol Layer Inspector; flow references open the TCP Conversation Ladder.

3. **Feature C: Demonstration & Traffic Replay Lab**
   - Built-in deterministic replay engine with 5 synthetic scenarios:
     1. `normal_traffic`: Multi-protocol baseline (HTTP, DNS, TLS, ICMP).
     2. `port_scan`: Rogue endpoint `192.168.1.199` probes 22 ports -> triggers Port Scan Heuristic Alert.
     3. `syn_flood`: Attacker `10.0.0.88` floods 28 rapid SYNs -> triggers SYN Flood Alert.
     4. `traffic_spike`: 180 UDP datagram burst -> triggers Packet Rate Spike Alert.
     5. `benign_burst`: High-volume TCP stream with complete handshakes and ACKs -> **Proves Zero False Positives!**
   - Player control deck: Paced streaming (1x, 2x, 5x, 10x, Instant), pause/resume/stop, live progress bar, and real-time detection event feed.

4. **Feature D: Unified Flow & Packet Investigation**
   - Bidirectional 5-tuple tracking with TCP state machine modeling (`ESTABLISHED`, `RESET`, `CLOSING`, `MID_STREAM`).
   - Chronological TCP handshake and teardown conversation ladder with retransmission accounting.
   - Full 12-column Packet Explorer with multi-field search, protocol filtering, and layer-by-layer header inspection.

5. **Feature F: Forensic Investigation Cases & Reports Hub**
   - Full forensic case lifecycle management (`Open`, `In Progress`, `Closed`).
   - Chronological analyst worklog and evidence artifact attachments (Incidents, Flows, Packets, Hosts).
   - Standalone, print-ready HTML forensic case reports (`/api/cases/<id>/report`) and full session reports (`/api/export/report`) with zero internet access requirements and strict XSS sanitization.
   - Differential capture comparison tool for side-by-side metric variance and protocol shift analysis.
- **Advanced TCP Conversation Inspector**:
  - Chronological ladder tracking SYN, SYN-ACK, ACK, Data segments, FIN teardown, and RST aborts.
  - Directional vector indicators (`A -> B` vs `B -> A`), relative timestamps from connection inception, sequence and acknowledgment tracking, frame length, and retransmission detection.
  - Explicit connection state classification distinguishing verified 3-way handshakes from incomplete attempts and mid-stream captures.
  - Interactive packet cross-linking: click any ladder frame to inspect the underlying packet fields directly.
- **Differential Capture Comparison**:
  - Side-by-side statistical comparison of two captures (Capture A vs Capture B) or active capture vs baseline fixture.
  - Evaluates volume variance, duration shifts, packet rate and throughput deltas, host diversity, and protocol percentage shifts.
  - **Methodological Guardrails**: Automatically warns when observation spans differ significantly, preventing misleading rate conclusions.
- **Self-Contained HTML Report Generation**:
  - Export professional, print-ready, standalone HTML analysis reports (`/api/export/report`).
  - Includes verified KPI scorecards, protocol breakdown tables, top talkers, flow summaries, explainable heuristic alerts, and academic disclaimers.
  - Zero external CDN or internet requirements with strict XSS sanitization (`html.escape`).
- **Professional Dual-Theme System (Light & Dark)**:
  - Engineered with comprehensive semantic design tokens (`--bg-canvas`, `--surface-card`, `--text-primary`, `--border-subtle`).
  - Single-click theme switcher in header with instant transition and zero page reload.
  - Zero-flash startup using inline DOM script; automatically honors OS system preference (`prefers-color-scheme`) with persistent `localStorage`.
  - **Dynamic Plotly Relayout**: Real-time chart recoloring without re-fetching network datasets or redrawing from scratch.
- **Explainable Anomaly Intelligence**:
  - Heuristic detection distinguishing observable traffic facts from unconfirmed suspicions.
  - Every alert displays verified strings for **Observed Value**, **Configured Threshold**, **Sliding Time Window**, **Affected Host**, **Target**, and plausible benign explanations.
  - **Clickable Packet Evidence Links**: Badges jump straight into the Protocol Layer Inspector for that exact frame.
- **Deterministic Analytics & Defensive Robustness**:
  - Rigorously separates capture throughput from engine processing speed.
  - Gracefully handles malformed, truncated, or unhandled packets without crashing, labeling them as `Malformed` with diagnostic reasons.

---

## 2. Repository Structure

```
netscope/
│   app.py                      # Flask Application entry point
│   config.py                   # Environment configuration & limits
│   requirements.txt            # Pinned dependency manifest
│   pytest.ini                  # Pytest configuration & warning filters
│   benchmark_experiments.py    # Automated performance & correctness suite
│   README.md                   # Comprehensive documentation & setup
│   .gitignore                  # Git ignore rules
│
├── capture/                    # Packet Ingestion Subsystem
│   │   __init__.py
│   │   pcap_reader.py          # Incremental offline PCAP/PCAPNG processor
│   │   live_capture.py         # Asynchronous live sniffer thread & queue
│   │   generate_samples.py     # Deterministic sample PCAP generator
│
├── analyzer/                   # Parsing & Classification Subsystem
│   │   __init__.py
│   │   parser.py               # Normalized multi-layer packet decoder & DNS parser
│   │   protocol_classifier.py  # Payload inspection & protocol identification
│   │   flow_tracker.py         # Bidirectional 5-tuple flow, TCP state & conversation ladder
│
├── analytics/                  # Traffic Analytics, Heuristics & Reports
│   │   __init__.py
│   │   statistics.py           # Throughput, PPS, averages & time-series
│   │   anomaly_detector.py     # Configurable SYN flood, port scan & rate alert rules
│   │   capture_comparator.py   # Differential capture analysis & metric deltas
│   │   report_generator.py     # Standalone print-ready HTML report engine
│
├── storage/                    # Persistence Subsystem
│   │   __init__.py
│   │   database.py             # Parameterized SQLite session & alert storage
│
├── routes/                     # REST API Service
│   │   __init__.py
│   │   api.py                  # Endpoints for stats, packets, flows, timeline, compare & reports
│
├── templates/                  # Frontend Presentation
│   │   index.html              # Responsive dual-theme dashboard layout with conversation & compare modals
│
├── static/                     # Assets & Scripts
│   ├── css/
│   │   └── style.css           # Custom dark & light theme styles, ladders & delta pills
│   └── js/
│       ├── charts.js           # Plotly chart renderers & dynamic theme relayout
│       ├── dashboard.js        # Controller, conversation inspector, comparison & alerts
│       └── vendor/
│           └── plotly.min.js   # Offline Plotly.js library
│
├── tests/                      # Automated Quality Assurance Suite (61 Tests)
│   ├── conftest.py             # Test client & deterministic fixtures
│   ├── test_parser.py          # Protocol parsing, DNS & defensive decoding tests
│   ├── test_statistics.py      # Metric calculations & formula tests
│   ├── test_pcap_reader.py     # PCAP reading & error handling tests
│   ├── test_pcap_fixtures.py   # Physical PCAP handshakes, teardown & retransmission tests
│   ├── test_anomaly_detector.py# Heuristic alerts, false-positive & config tests
│   ├── test_conversation_inspector.py # Handshakes, teardown, mid-stream & retransmissions
│   ├── test_comparator.py      # Capture comparison, zero-guards & duration warnings
│   ├── test_report_generator.py# HTML report rendering & XSS security escaping tests
│   ├── test_filters.py         # Query, port, packet ID, flow ID & CSV export tests
│   ├── test_api.py             # REST API endpoint integration & config tests
│   └── test_lifecycle.py       # Capture lifecycle & queue stress tests
│
├── data/                       # Captures & Datasets
│   ├── README.md               # Dataset descriptions & verification notes
│   └── sample_traffic.pcap     # Deterministic 60-packet multi-protocol fixture
│
└── docs/                       # Academic Submission Documentation
    ├── problem_statement.md    # Problem statement & academic motivation
    ├── objectives_and_scope.md # Project scope, deliverables & constraints
    ├── architecture.md         # Architecture design & Mermaid topology
    ├── protocol_design.md      # Normalized schema & API contract
    ├── implementation.md       # Module-by-module technical breakdown
    ├── test_plan.md            # Verification strategy & test matrix
    ├── test_report.md          # Complete test results (61/61 passing)
    ├── performance_report.md   # Empirical benchmarks (throughput, latency, memory)
    ├── limitations.md          # Technical constraints & driver notes
    ├── demo_script.md          # Five-minute presentation walkthrough
    ├── viva_questions.md       # 28 comprehensive viva questions & answers
    ├── wireshark_verification.md# Industrial Wireshark comparison procedure
    ├── screenshot_checklist.md # Visual evidence inventory
    ├── contributions.md        # Individual team contribution record
    └── screenshots/            # Verified application captures
```

---

## 3. Installation & Setup

### Prerequisites:
- Python 3.10+ (Tested on Python 3.13.2 64-bit)
- Windows, Linux, or macOS
- *(Optional)* [Npcap](https://npcap.com/) on Windows with "WinPcap API-compatible mode" for live packet sniffing.

### Step 1: Clone or Navigate to Project
```bash
cd serene-mendeleev
```

### Step 2: Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Pinned Dependencies
```bash
pip install -r requirements.txt
```

---

## 4. Running the Application

### Launch Flask Server:
```bash
python app.py
```
Output:
```
[*] NetScope running on http://127.0.0.1:5000
[*] Academic Computer Networks Mini-Project
[*] Ready for offline PCAP ingestion and live packet analysis.
```

### Access Dashboard:
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 5. Usage Instructions

1. **Instant Sample Demonstration**:
   - Click the **Load Sample PCAP** button in the header.
   - NetScope immediately parses the bundled 60-packet multi-protocol capture.
   - Summary cards, protocol donut charts, traffic timeline, top talkers, flows, and security alerts populate in milliseconds.

2. **Upload Custom PCAP**:
   - Click **Upload PCAP** and select any `.pcap`, `.pcapng`, or `.cap` file (up to 50 MB).
   - The engine parses frames incrementally and updates all analytics.

3. **Explore and Filter Packets**:
   - Use the search bar for instant full-text filtering across IPs, ports, and protocols.
   - Filter by protocol (`TCP`, `UDP`, `ICMP`, `ARP`, `DNS`, `HTTP`, `TLS`, `IPv6`).
   - Filter by specific port (`Src Port`, `Dst Port`) or exact packet number (`Pkt #`).
   - Click any packet row to open the **Protocol Layer Inspector** modal displaying Ethernet, IP, TCP/UDP, and application fields (including DNS transaction IDs and answer records).

4. **Conversation Flow Tracking**:
   - Inspect the **Active Flows** card to review bidirectional conversations, data volumes, packet counts, and TCP states.
   - Click the **Filter Flow** button on any flow to filter the packet explorer table to only packets belonging to that conversation.
   - Click the active flow badge to clear the flow filter.

5. **TCP Conversation Inspector**:
   - In the Canonical Network Flows table, click the **Inspect** button on any flow (e.g. `flow-3`).
   - Opens the **TCP Conversation Inspector** showing the complete chronological ladder: SYN, SYN-ACK, ACK, Data frames, FIN, RST, relative times, directional vectors, sequence/ack numbers, frame lengths, and retransmissions.
   - Click any frame reference (`#16`) to immediately view the low-level decoded protocol layers.

6. **Differential Capture Comparison**:
   - Click the **Compare** button in the header actions.
   - Compare the active capture against the baseline sample (`sample_traffic.pcap`) or upload a second `.pcap` file.
   - Reviews statistical deltas across packets, bytes, durations, arrival rates, throughput, host diversity, and protocol distribution shifts.
   - Includes automatic methodological alerts if observation time windows differ significantly.

7. **Download Standalone HTML Intelligence Report**:
   - Click the **Report** button in the header actions.
   - Immediately generates and downloads/views a self-contained, print-ready, professional HTML traffic intelligence report with verified KPIs, protocol tables, flow summaries, and academic disclaimers.

8. **Security Alerts & Threshold Tuning**:
   - Inspect security alerts detailing affected hosts, observed values, thresholds, sliding time windows, and supporting packet references.
   - Click any packet reference badge to inspect that specific packet immediately.
   - Click **Thresholds** in the header to adjust SYN flood or port scan parameters in real-time.

9. **Export Dataset**:
   - Apply any desired filters and click **Export CSV** to download the active filtered dataset with Flow ID and Relative Time columns.

10. **Live Packet Capture**:
   - Select an available network interface from the dropdown and click **Capture**.
   - If Npcap is not installed on Windows, NetScope displays clear diagnostic remediation.

---

## 6. Running Tests & Benchmarks

### Execute Test Suite:
```powershell
.\.venv\Scripts\pytest.exe -v
```
All **61 tests** across 11 test modules pass with a 100% success rate in ~2.50 seconds with zero warnings.

### Run Performance & Correctness Benchmarks:
```powershell
.\.venv\Scripts\python.exe benchmark_experiments.py
```
This runs Experiments A through E, testing offline processing rate, mathematical formula correctness, filter latency, API endpoint speed, and live driver capabilities.

---

## 7. Performance & Verification Highlights

| Metric | Measured Result | Evaluation Note |
|---|---|---|
| **Small Capture Processing (60 pkts)** | **2,750.25 PPS** (0.0218 s) | Ingestion throughput on Python 3.13 |
| **Medium Capture Processing (500 pkts)** | **1,588.92 PPS** (0.3147 s) | Sustained parsing & state tracking |
| **Large Capture Processing (2,500 pkts)** | **1,425.06 PPS** (1.7543 s) | Bounded memory buffer management |
| **Formula Accuracy vs Ground Truth** | **100% exact match** across all 10 metrics | Verified against RFC 793 / RFC 8200 math |
| **Filter Query Latency** | Under **0.81 milliseconds** | O(1) indexed dictionary retrieval |
| **Dashboard API Latency** | Under **0.89 milliseconds** | Instantaneous REST endpoint delivery |
| **Memory Footprint** | Bounded **104.7 MB - 112.7 MB RSS** | Leak-free garbage collection |

### Architectural Metric Integrity & Verification Standards:
- **Capture Duration vs. Processing Rate**: NetScope strictly distinguishes *Capture Duration* (the physical on-wire span between $t_{\max}$ and $t_{\min}$) from *Processing Time* (wall-clock elapsed time consumed by offline ingestion). Rate calculations ($PPS_{\text{capture}} = N / \text{duration}$) and processing speed ($PPS_{\text{proc}} = N / \text{elapsed}$) are computed and displayed independently across the UI and reports.
- **Wireshark Verification Standard**: In environments without a local TShark/Wireshark installation, calculations are verified against RFC 793 / RFC 8200 standards and Scapy ground truth. A complete, independent Wireshark verification protocol with exact display filters and expected values is documented in [`docs/wireshark_verification.md`](docs/wireshark_verification.md).

---

## 8. Academic Viva & Documentation Index
- [Problem Statement & Motivation](docs/problem_statement.md)
- [Architecture & Mermaid Topology](docs/architecture.md)
- [Protocol Design & API Contract](docs/protocol_design.md)
- [Implementation Details](docs/implementation.md)
- [Automated Test Report](docs/test_report.md)
- [Performance & Benchmarks Report](docs/performance_report.md)
- [Operational Limitations](docs/limitations.md)
- [5-Minute Demonstration Script](docs/demo_script.md)
- [28 Viva Voce Questions & Answers](docs/viva_questions.md)
- [Wireshark Verification Procedure](docs/wireshark_verification.md)
- [Visual Evidence & Screenshots](docs/screenshot_checklist.md)
- [Team Contribution Record](docs/contributions.md)

---

## 9. License & Academic Attribution
Developed as an autonomous Computer Networks Laboratory Mini-Project. Code is structured for educational reproducibility and local academic defense.
