# NetScope: Visual Evidence & Screenshot Checklist

This checklist documents the graphical visual evidence generated for project submission and oral presentation.

---

## Screenshot Inventory

| Screenshot ID | Target View | File Path | Status | Verification Note |
|---|---|---|---|---|
| **SS-01** | NetScope 2.0 Dark Theme Dashboard | `docs/screenshots/dashboard_dark.png` | **Captured (Real)** | High-res 1560x1100 headless Chrome capture showing dark theme, summary cards, Plotly charts, alerts, and packet grid |
| **SS-02** | NetScope 2.0 Light Theme Dashboard | `docs/screenshots/dashboard_light.png` | **Captured (Real)** | High-res 1560x1100 headless Chrome capture showing light theme with WCAG AA contrast and adaptive charts |
| **SS-03** | Packet Inspector Modal | `docs/screenshots/packet_inspector_modal.png` | **Captured (Real)** | Real capture showing multi-layer protocol breakdown, TCP flags, and hex payload viewer |
| **SS-04** | Security Alerts & Anomaly Details | `docs/screenshots/security_alerts.png` | **Captured (Real)** | Real capture showing anomaly cards with exact observed values, thresholds, sliding windows, and packet references |
| **SS-05** | Legacy Dashboard Overview | `docs/screenshots/dashboard_overview.png` | Captured (Archive) | Initial version 1.0 baseline capture |
| **SS-06** | Automated Test Output | `docs/test_report.md` | Terminal Output Verified | 55 passed tests in 3.03 seconds (100% pass rate) |
| **SS-07** | Wireshark Side-by-Side | `docs/wireshark_verification.md` | Procedure Ready | Dual-verification procedure documenting Scapy vs Wireshark metrics |
| **SS-08** | TCP Conversation Inspector | `docs/screenshots/tcp_conversation_inspector.png` | **Captured (Real)** | NetScope 3.0 chronological ladder diagram with SYN/ACK state machine, retransmission flags, and frame cross-links |
| **SS-09** | Differential Capture Comparison | `docs/screenshots/capture_comparison.png` | **Captured (Real)** | NetScope 3.0 side-by-side PCAP comparison with delta pills, protocol shifts, and disparate duration warning |
| **SS-10** | Standalone HTML Intelligence Report | `docs/screenshots/html_report_preview.png` | **Captured (Real)** | NetScope 3.0 standalone self-contained HTML report with KPI scorecard, protocol analysis, and academic disclaimers |

---

## Instructions for Taking Additional User Screenshots
To take interactive screenshots in full browser resolution:
1. Start NetScope:
   ```bash
   python app.py
   ```
2. Navigate to `http://127.0.0.1:5000` in Google Chrome or Microsoft Edge.
3. Click **Load Sample PCAP** to populate the dashboard with realistic traffic.
4. Click any packet row to inspect the Protocol Layer Modal.
5. Capture screenshot using `Windows + Shift + S` or Chrome Developer Tools (`Ctrl + Shift + P` -> "Capture full size screenshot").
