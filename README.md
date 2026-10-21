# NetScope: Real-Time Network Packet Analyzer & Traffic Intelligence Dashboard

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8.0-red.svg)](https://scapy.net/)
[![Tests](https://img.shields.io/badge/Tests-55%20Passed-emerald.svg)](docs/test_report.md)
[![Themes](https://img.shields.io/badge/UI-Dark%20%7C%20Light%20Modes-indigo.svg)]()
[![Academic](https://img.shields.io/badge/Category-Computer%20Networks%20Mini--Project-purple.svg)]()

> **Computer Networks Laboratory Mini-Project Deliverable (Release 3.0 Excellence Upgrade)**  
> An autonomous, mathematically verified network packet analyzer, statistical intelligence engine, stateful TCP conversation inspector, differential capture comparator, and interactive professional web dashboard with dual Light/Dark theme support.

---

## NetScope 3.0 Visual Interface Gallery

| TCP Conversation Inspector (Ladder Progression) | Differential Capture Comparison |
|:---:|:---:|
| ![TCP Conversation Inspector](docs/screenshots/tcp_conversation_inspector.png) | ![Capture Comparison](docs/screenshots/capture_comparison.png) |

| Self-Contained HTML Intelligence Report | Dark Theme Dashboard Overview |
|:---:|:---:|
| ![HTML Report Preview](docs/screenshots/html_report_preview.png) | ![NetScope Dark Theme Dashboard](docs/screenshots/dashboard_dark.png) |

| Light Theme (Auditorium & Print Mode) | Deep Packet Protocol Inspector |
|:---:|:---:|
| ![NetScope Light Theme Dashboard](docs/screenshots/dashboard_light.png) | ![Packet Inspector Modal](docs/screenshots/packet_inspector_modal.png) |

---

## 1. Project Overview & Highlights
NetScope ingests network packet captures (offline `.pcap` / `.pcapng` files and live network interfaces), parses multi-layer protocols, computes academically verified traffic metrics, detects stateful security anomalies (SYN floods, port scans), groups conversations into 5-tuple flows, inspects TCP connection lifecycles, compares capture runs side-by-side, and visualizes results on an interactive web dashboard with zero external CDN dependencies.

### What's New in NetScope 3.0:
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
├── tests/                      # Automated Quality Assurance Suite
│   │   conftest.py             # Test client & deterministic fixtures
│   │   test_parser.py          # Protocol parsing, DNS & defensive decoding tests
│   │   test_statistics.py      # Metric calculations & formula tests
│   │   test_pcap_reader.py     # PCAP reading & error handling tests
│   │   test_anomaly_detector.py# Heuristic alerts, false-positive & config tests
│   │   test_conversation_inspector.py # Handshakes, teardown, mid-stream & retransmissions
│   │   test_comparator.py      # Capture comparison, zero-guards & duration warnings
│   │   test_report_generator.py# HTML report rendering & XSS security escaping tests
│   │   test_filters.py         # Query, port, packet ID, flow ID & CSV export tests
│   │   test_api.py             # REST API endpoint integration & config tests
│   │   test_lifecycle.py       # Capture lifecycle & queue stress tests
│
├── data/                       # Captures & Datasets
│   │   README.md               # Dataset descriptions & verification notes
│   │   sample_traffic.pcap     # Deterministic 60-packet multi-protocol fixture
│
└── docs/                       # Academic Submission Documentation
    ├── problem_statement.md    # Problem statement & academic motivation
    ├── objectives_and_scope.md # Project scope, deliverables & constraints
    ├── architecture.md         # Architecture design & Mermaid topology
    ├── protocol_design.md      # Normalized schema & API contract
    ├── implementation.md       # Module-by-module technical breakdown
    ├── test_plan.md            # Verification strategy & test matrix
    ├── test_report.md          # Complete test results (55/55 passing)
    ├── performance_report.md   # Empirical benchmarks (throughput, latency, memory)
    ├── limitations.md          # Technical constraints & driver notes
    ├── demo_script.md          # Five-minute presentation walkthrough
    ├── viva_questions.md       # 28 comprehensive viva questions & answers
    ├── wireshark_verification.md# Industrial Wireshark comparison procedure
    ├── screenshot_checklist.md # Visual evidence inventory
    ├── contributions.md        # Individual team contribution record
    └── screenshots/            # Verified application captures
```
    ├── architecture.md         # Architecture design & Mermaid topology
    ├── protocol_design.md      # Normalized schema & API contract
    ├── implementation.md       # Module-by-module technical breakdown
    ├── test_plan.md            # Verification strategy & test matrix
    ├── test_report.md          # Complete test results (41/41 passing)
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
All **55 tests** pass with 100% success rate in ~3.03 seconds.

### Run Performance & Correctness Benchmarks:
```powershell
.\.venv\Scripts\python.exe benchmark_experiments.py
```
This runs Experiments A through E, testing offline processing rate, mathematical formula correctness, filter latency, API endpoint speed, and live driver capabilities.

---

## 7. Performance & Verification Highlights

| Metric | Measured Result |
|---|---|
| **Small Capture Processing (60 pkts)** | **2,750.25 PPS** (0.0218 s) |
| **Medium Capture Processing (500 pkts)** | **1,588.92 PPS** (0.3147 s) |
| **Large Capture Processing (2,500 pkts)** | **1,425.06 PPS** (1.7543 s) |
| **Formula Accuracy vs Ground Truth** | **100% exact match** across all 10 metrics |
| **Filter Query Latency** | Under **0.81 milliseconds** across all queries |
| **Dashboard API Latency** | Under **0.89 milliseconds** across all endpoints |
| **Memory Footprint** | Bounded **104.7 MB - 112.7 MB RSS** |

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
