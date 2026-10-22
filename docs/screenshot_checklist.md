# NetScope: Visual Evidence & Screenshot Checklist

This checklist documents the graphical visual evidence generated for project submission and oral presentation.

---

## Screenshot Inventory

| Screenshot ID | Target View | File Path | Status | Verification Note |
|---|---|---|---|---|
| **SS-01** | NetScope Dark Theme Dashboard | `docs/screenshots/dashboard_dark.png` | **Captured (Real)** | High-res 1600x1050 capture showing refined graphite theme, precision sidebar, KPI scorecards, adaptive donut & timeline charts, and alerts |
| **SS-02** | NetScope Light Theme Dashboard | `docs/screenshots/dashboard_light.png` | **Captured (Real)** | High-res 1600x1050 capture showing warm off-white surface, crisp contrast, teal accents, and adaptive charts |
| **SS-03** | Packet Stream Table & Explorer | `docs/screenshots/packet_stream.png` | **Captured (Real)** | High-res capture showing dense, monospace packet grid with relative offsets, directional badges, protocol badges, and TCP flag chips |
| **SS-04** | Packet Inspector Modal | `docs/screenshots/packet_inspector_modal.png` | **Captured (Real)** | Real capture showing layered protocol cards (Ethernet, IPv4, UDP, DNS), parsed fields, and raw metadata |
| **SS-05** | Security Alerts & Anomaly Details | `docs/screenshots/security_alerts.png` | **Captured (Real)** | Real capture showing heuristic security intelligence cards with exact observed values, thresholds, sliding windows, and packet references |
| **SS-06** | Automated Test Output | `docs/test_report.md` | Terminal Output Verified | 61 passed tests in 1.56 seconds (100% pass rate, 0 warnings) |
| **SS-07** | Wireshark Side-by-Side | `docs/wireshark_verification.md` | Procedure Ready | Dual-verification procedure documenting Scapy vs Wireshark metrics |
| **SS-08** | TCP Conversation Inspector | `docs/screenshots/tcp_conversation_inspector.png` | **Captured (Real)** | Chronological ladder diagram with SYN/ACK state machine, directional vectors, retransmission flags, and frame cross-links |
| **SS-09** | Differential Capture Comparison | `docs/screenshots/capture_comparison.png` | **Captured (Real)** | Side-by-side PCAP comparative differential with delta metrics, protocol shifts, and duration warnings |
| **SS-10** | Standalone HTML Intelligence Report | `docs/screenshots/html_report_preview.png` | **Captured (Real)** | Standalone self-contained HTML report with KPI scorecard, protocol analysis, and academic disclaimers |

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
