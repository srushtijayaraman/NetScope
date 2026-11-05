# NetScope X: 5-Minute Live Academic & Industry Demonstration Guide

> **Project:** NetScope X — Autonomous Network Intelligence & Security Forensics Platform  
> **Author:** Srushti Jayaraman  
> **Target Audience:** Professors, Academic Evaluators, Senior Network Engineers, Cybersec Analysts  
> **Execution Environment:** 100% Localhost (Python 3.14 / Flask 3.1.3 / Scapy / SQLite / Vanilla JS & CSS)  
> **Internet / External CDN Dependencies:** ZERO (Offline local Plotly.js and embedded vector icons)

---

## Pre-Demonstration Setup (30 Seconds)

1. Open PowerShell or Command Prompt in the repository folder:
   ```powershell
   .\.venv\Scripts\activate
   python app.py
   ```
2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```
3. Toggle between **Dark Mode** and **Light Mode** using the top-right button to demonstrate semantic theme persistence. (We recommend **Dark Mode** for the best cyber/SOC visual presentation).

---

## 5-Minute Demonstration Script

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MINUTE 1: Platform Overview & Autonomous Architecture                      │
│ MINUTE 2: Replay Lab & Deterministic Scenarios (Zero False Positive Proof)  │
│ MINUTE 3: Security Incident Center & Explainable SOC Engine (Facts vs Hyp) │
│ MINUTE 4: Interactive Network Topology (RFC 1918 Graph & Host Inspector)   │
│ MINUTE 5: Forensic Case Investigation & Standalone HTML Report Export      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

### Minute 1: Platform Overview & Autonomous Architecture
* **Spoken Pitch:**  
  *"Welcome. This is NetScope X, an autonomous network traffic intelligence and cyber forensics platform. Rather than a static packet viewer, NetScope X operates as a real-time, stateful telemetry engine capable of bidirectional conversation reconstruction, deterministic heuristic threat detection, and forensic evidence tracking."*
* **Actions:**
  1. Point out the **Left Navigation Rail** organizing the platform into 9 views:
     * *Core Telemetry:* Overview, Live Monitor, Network Map
     * *Deep Inspection:* Packet Explorer, Flows & Conversation Ladder
     * *SOC Operations:* Security Incidents, Replay Lab, Investigations, Reports & Diff
  2. Click **"Load Sample"** in the top navigation bar to populate multi-protocol baseline traffic (HTTP, DNS, TLS, ICMP).
  3. Show the **Executive Metric Cards**: Total Packets, Total Volume, Throughput (kbps / Mbps), Host & Flow diversity.
  4. Highlight the **Protocol Distribution donut** and the **1-Second Traffic Timeline chart**.

---

### Minute 2: Demonstration Lab & Deterministic Scenarios (Feature C)
* **Spoken Pitch:**  
  *"To demonstrate reproducible network security evaluations in live academic settings, NetScope X includes a deterministic Traffic Replay Lab with 5 synthetic attack and baseline scenarios."*
* **Actions:**
  1. Click **"Replay Lab"** in the left sidebar.
  2. **Highlight the Zero False Positive Proof (Scenario 5):**
     * Click **"Run Benign Burst Scenario"** at **5x** or **Instant** speed.
     * Point out that despite 53 rapid, high-volume TCP segments, because the 3-way handshake and ACK stream are valid, the engine fires **0 alerts**.
  3. **Launch the Attack Scenario (Scenario 2):**
     * Click **"Run Port Scan Scenario"**.
     * Watch the **animated progress bar**, packet arrival counter, and the **Live Demonstration Detection Feed** in real-time.
     * The feed immediately reports:  
       `🔴 Anomaly Detected: Port Scan Heuristic Violation — 22 distinct ports probed by 192.168.1.199`.

---

### Minute 3: Security Incident Center & Explainable SOC Engine (Features B & E)
* **Spoken Pitch:**  
  *"Unlike traditional intrusion detectors that produce opaque alert logs, NetScope X provides an Explainable SOC Detection Engine that explicitly separates observable network facts from hypotheses and benign explanations."*
* **Actions:**
  1. Click **"Incidents"** in the sidebar (notice the warning pill counter has updated).
  2. Click the newly correlated **Port Scan incident card** to slide open the **Incident Forensic Drawer**.
  3. Walk the evaluators through the 3 explainability sections:
     * **Observable Facts (Deterministic):** Exact 22 distinct destination ports probed within a 1.76-second window with TCP SYN flags.
     * **Security Hypothesis:** Active reconnaissance scanning by rogue endpoint `192.168.1.199`.
     * **Alternative Benign Explanations:** Legitimate Nessus vulnerability assessment or network management audit.
  4. Click on an **Evidence Packet chip (`#Pkt 12`)**:
     * Instantly opens the **Protocol Layer Inspector** displaying Ethernet MACs, IPv4 headers, and TCP SYN flags.
  5. In the drawer, change Workflow Status from `New` to **`Investigating`**.
  6. In the **Analyst Notes** box, type: `"Attacker confirmed rogue endpoint 192.168.1.199; escalating to forensic case."` and click **Add**.

---

### Minute 4: Interactive Network Topology (Feature A)
* **Spoken Pitch:**  
  *"NetScope X automatically categorizes network addressing and visualizes communication intensity as an interactive topology graph."*
* **Actions:**
  1. Click **"Network Map"** in the sidebar.
  2. Point out the interactive visual features:
     * **Internal Endpoints (RFC 1918):** Rendered in emerald green on the inner orbit.
     * **External Endpoints:** Rendered in indigo along the outer orbit.
     * **Attacker Host (`192.168.1.199`):** Rendered with a prominent, pulsating crimson threat halo!
     * **Edge Streams:** Dynamic flow lines with moving particle pulses showing real-time directionality and intensity.
  3. Click on the red attacker node **`192.168.1.199`**:
     * The **Host Inspector Drawer** slides open showing total volume, sent/recv ratios, connected peers, and active 5-tuples.
  4. Click **"Filter Packet Explorer to this Host"**:
     * The platform jumps directly to **Packet Explorer**, pre-filtering the 12-column table to only packets involving `192.168.1.199`.

---

### Minute 5: Forensic Case Investigation & Standalone HTML Report Export (Feature F)
* **Spoken Pitch:**  
  *"To close the loop from detection to remediation, NetScope X includes a full forensic investigation management suite and exports self-contained, print-ready HTML reports."*
* **Actions:**
  1. Click **"Investigations"** in the sidebar.
  2. Click **"Create New Case"**:
     * Title: `Rogue Endpoint Port Scan Investigation`
     * Priority: `High`
     * Analyst: `Srushti Jayaraman - Lead Network Security Engineer`
     * Click **Create Investigation**.
  3. The **Case Detail Drawer** opens:
     * Click **"Add"** under Analyst Investigation Log to record remediation actions:  
       `"Perimeter ACL rule applied on router to drop all ingress frames from 192.168.1.199."`
     * Change status to **`Closed`**.
  4. Click **"Export Standalone Forensic Report (HTML)"**:
     * The browser opens the generated HTML report.
     * Point out that the report is **100% self-contained**, uses strict XSS escaping, contains all telemetry, evidence packet dumps, analyst notes, and academic verification marks.
     * Press `Ctrl + P` to show that the report is **print-ready and formatted for PDF export**.
  5. Return to **Replay Lab** and click **"Reset Lab"** to demonstrate clean state restoration.

---

## Key Technical Questions Evaluators Might Ask & Winning Answers

| Question | Winning Answer |
| :--- | :--- |
| **"How do you handle Scapy performance on Windows?"** | *"We decoupled raw frame parsing from real-time analytics. Offline files use chunked Scapy ingestion, whereas live captures utilize an asynchronous bounded ring-buffer queue (`MAX_MEMORY_PACKETS`) to guarantee zero UI lag and drop accounting under high PPS."* |
| **"How do you prevent False Positives during heavy bursts?"** | *"Our anomaly engine does not solely rely on raw packet rates. For example, the SYN flood heuristic tracks SYN-to-ACK ratios and unacknowledged handshakes. High-volume legitimate streams (demonstrated in Scenario 5) are recognized as valid TCP stateful sessions and trigger zero alerts."* |
| **"Where is the data stored?"** | *"All session metadata, heuristic alerts, correlated incidents, and investigation cases are persistently stored in an ACID-compliant local SQLite database with parameterized SQL queries preventing SQL injection."* |
| **"What external dependencies or CDNs are required?"** | *"Zero. Plotly.js is bundled locally in `static/js/vendor/plotly.min.js`, all styling uses Vanilla CSS custom properties, and network topology is rendered on a native HTML5 2D Canvas without D3 or cloud dependencies."* |
