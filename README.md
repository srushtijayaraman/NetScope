# NetScope: Real-Time Network Packet Analyzer & Traffic Intelligence Dashboard

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8.0-red.svg)](https://scapy.net/)
[![Tests](https://img.shields.io/badge/Tests-34%20Passed-emerald.svg)](docs/test_report.md)
[![Academic](https://img.shields.io/badge/Category-Computer%20Networks%20Mini--Project-purple.svg)]()

> **Computer Networks Laboratory Mini-Project Deliverable**  
> An autonomous, mathematically verified network packet analyzer, statistical intelligence engine, and interactive dark-mode web dashboard.

---

## 1. Project Overview & Highlights
NetScope ingests network packet captures (offline `.pcap` / `.pcapng` files and live network interfaces), parses multi-layer protocols, computes academically verified traffic metrics, detects stateful security anomalies (SYN floods, port scans), and visualizes the results on an interactive web dashboard with zero external CDN dependencies.

### Core Features:
- **Offline PCAP Ingestion**: Incremental, memory-bounded reading of PCAP/PCAPNG captures with stream closure guarantees.
- **Protocol Decoding**: Detailed extraction across Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS.
- **Strict Classification**: Validates application-layer payload byte signatures (HTTP verbs, TLS record headers) rather than guessing from port numbers alone.
- **Deterministic Analytics**: Throughput (bps/kbps/Mbps), packets-per-second (PPS), average packet size, capture duration, protocol percentages, and chronological time buckets.
- **Canonical Flow Tracking**: Symmetric 5-tuples `(IP A, IP B, Protocol, Port A, Port B)` tracking bidirectional volumes and TCP states (`SYN_SENT`, `SYN_ACK`, `ESTABLISHED`, `RESET`, `CLOSED`).
- **Explainable Anomaly Alerts**: Heuristic detection for TCP SYN floods, horizontal/vertical port scans, packet rate spikes, and dominant traffic hosts with cooldown deduplication.
- **Packet Explorer**: High-performance grid with sub-2ms search, combinable protocol/IP/port filters, pagination, click-to-inspect detail modal, and RFC 4180 CSV export.
- **Offline Readiness**: Self-contained frontend bundle with local Plotly.js (`plotly.min.js`), requiring no active internet connection.

---

## 2. Repository Structure

```
netscope/
│   app.py                      # Flask Application entry point
│   config.py                   # Environment configuration & limits
│   requirements.txt            # Pinned dependency manifest
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
│   │   parser.py               # Normalized multi-layer packet decoder
│   │   protocol_classifier.py  # Payload inspection & protocol identification
│   │   flow_tracker.py         # Bidirectional 5-tuple flow & TCP state tracker
│
├── analytics/                  # Traffic Analytics & Heuristics
│   │   __init__.py
│   │   statistics.py           # Throughput, PPS, averages & time-series
│   │   anomaly_detector.py     # SYN flood, port scan & volumetric alert rules
│
├── storage/                    # Persistence Subsystem
│   │   __init__.py
│   │   database.py             # Parameterized SQLite session & alert storage
│
├── routes/                     # REST API Service
│   │   __init__.py
│   │   api.py                  # Endpoints for stats, packets, alerts & CSV
│
├── templates/                  # Frontend Presentation
│   │   index.html              # Responsive dark navy dashboard layout
│
├── static/                     # Assets & Scripts
│   ├── css/
│   │   └── style.css           # Custom dark theme styles
│   └── js/
│       ├── charts.js           # Plotly chart renderers
│       ├── dashboard.js        # Controller, safe DOM rendering & polling
│       └── vendor/
│           └── plotly.min.js   # Offline Plotly.js library
│
├── tests/                      # Automated Quality Assurance Suite
│   │   conftest.py             # Test client & deterministic fixtures
│   │   test_parser.py          # Protocol parsing & decoders tests
│   │   test_statistics.py      # Metric calculations & formula tests
│   │   test_pcap_reader.py     # PCAP reading & error handling tests
│   │   test_anomaly_detector.py# Security heuristics & alert tests
│   │   test_filters.py         # Query, pagination & CSV export tests
│   │   test_api.py             # REST API endpoint integration tests
│   │   test_lifecycle.py       # Capture lifecycle & queue stress tests
│
├── data/                       # Captures & Datasets
│   │   README.md               # Dataset descriptions & verification notes
│   │   sample_traffic.pcap     # Deterministic 60-packet multi-protocol fixture
│
└── docs/                       # Academic Submission Documentation
    ├── problem_statement.md    # Problem statement & academic motivation
    ├── objectives_and_scope.md # Project scope, deliverables & constraints
    ├── architecture.md         # Architecture design & Mermaid diagram
    ├── protocol_design.md      # Normalized schema & API contract
    ├── implementation.md       # Module-by-module technical breakdown
    ├── test_plan.md            # Verification strategy & test matrix
    ├── test_report.md          # Complete test results (34/34 passing)
    ├── performance_report.md   # Benchmarks (throughput, latency, memory)
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
   - Click any packet row to open the **Protocol Layer Inspector** modal displaying Ethernet, IP, TCP/UDP, and application fields.

4. **Export Dataset**:
   - Apply any desired filters and click **Export CSV** to download the active filtered dataset.

5. **Live Packet Capture**:
   - Select an available network interface from the dropdown and click **Capture**.
   - If Npcap is not installed on Windows, NetScope displays clear diagnostic remediation.

---

## 6. Running Tests & Benchmarks

### Execute Test Suite:
```bash
pytest -v
```
All **34 tests** pass with 100% success rate in ~0.40 seconds.

### Run Performance & Correctness Benchmarks:
```bash
python benchmark_experiments.py
```
This runs Experiments A through E, testing offline processing rate, mathematical formula correctness, filter latency, API endpoint speed, and live driver capabilities.

---

## 7. Performance & Verification Highlights

| Metric | Measured Result |
|---|---|
| **Small Capture Processing (60 pkts)** | 1,102 PPS (0.054 s) |
| **Medium Capture Processing (500 pkts)** | 996 PPS (0.501 s) |
| **Large Capture Processing (2,500 pkts)** | 546 PPS (4.57 s) |
| **Formula Accuracy vs Ground Truth** | 100% exact match across all 10 metrics |
| **Filter Query Latency** | Under 1.8 milliseconds across all queries |
| **Dashboard API Latency** | Under 1.6 milliseconds across all endpoints |
| **Memory Footprint** | Bounded ~105 MB - 112 MB RSS |

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
