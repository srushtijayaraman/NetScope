# NetScope: Visual Evidence & Screenshot Checklist

This checklist documents the graphical visual evidence generated for project submission and oral presentation.

---

## Screenshot Inventory

| Screenshot ID | Target View | File Path | Status | Verification Note |
|---|---|---|---|---|
| **SS-01** | Full Dashboard Overview | `docs/screenshots/dashboard_overview.png` | **Captured (Real)** | High-res 1600x1200 headless capture showing summary cards, Plotly charts, alerts, and packet grid |
| **SS-02** | Protocol Distribution Donut | `docs/screenshots/protocol_distribution.png` | Documented / In-Dashboard | Rendered via Plotly.js inside `dashboard_overview.png` |
| **SS-03** | Traffic Timeline (PPS / Kbps)| `docs/screenshots/traffic_timeline.png` | Documented / In-Dashboard | Shows chronological burst trends |
| **SS-04** | Top Talkers & Flows | `docs/screenshots/top_talkers_flows.png` | Documented / In-Dashboard | Displays endpoint host ranking and canonical 5-tuples |
| **SS-05** | Security Alerts Panel | `docs/screenshots/security_alerts.png` | Documented / In-Dashboard | Highlights SYN Flood (`HIGH`) and Port Scan (`MEDIUM`) alerts |
| **SS-06** | Packet Explorer Grid | `docs/screenshots/packet_explorer.png` | Documented / In-Dashboard | Shows paginated table, protocol badges, and search bar |
| **SS-07** | Automated Test Output | `docs/test_report.md` | Terminal Output Verified | 34 passed tests in 0.40 seconds |
| **SS-08** | Wireshark Side-by-Side | `docs/wireshark_verification.md` | Procedure Ready | Outstanding on current machine (Wireshark not installed) |

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
