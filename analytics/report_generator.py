"""
NetScope HTML Report Generator
Generates self-contained, print-ready, professional HTML analysis reports
for offline network packet captures.
Includes verified metrics, protocol distributions, top talkers, flow summaries,
explainable heuristic alerts, academic disclaimers, and mathematical definitions.
Guarantees strict HTML escaping to prevent XSS. Zero external CDN dependencies.
"""

import html
from datetime import datetime, timezone


def generate_html_report(
    summary: dict,
    protocols: dict,
    top_talkers: dict,
    top_flows: list[dict],
    alerts: list[dict],
    filename: str = "capture.pcap",
    capture_id: str = "default",
) -> str:
    """
    Renders a standalone, fully-styled HTML report document.
    All strings are safely escaped using html.escape.
    """
    gen_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    clean_filename = html.escape(str(filename or "Unknown Capture"))
    clean_capture_id = html.escape(str(capture_id or "default"))

    # Metrics
    total_packets = summary.get("total_packets", 0)
    total_bytes = summary.get("total_bytes", 0)
    duration = summary.get("capture_duration_seconds", 0.0)
    proc_time = summary.get("processing_time_seconds", 0.0)
    capture_pps = summary.get("capture_pps", 0.0)
    proc_pps = summary.get("processing_pps", 0.0)
    avg_pkt_size = summary.get("average_packet_size_bytes", 0.0)
    throughput_kbps = summary.get("throughput_kbps", 0.0)
    throughput_mbps = summary.get("throughput_mbps", 0.0)
    unique_hosts = summary.get("unique_hosts", 0)
    active_flows = summary.get("active_flows", len(top_flows))
    parsing_errors = summary.get("parsing_errors", 0)

    # Protocols Table
    proto_rows = []
    transport_dict = protocols.get("transport", {})
    for proto_name, pinfo in transport_dict.items():
        proto_rows.append(f"""
        <tr>
            <td><strong>{html.escape(proto_name)}</strong> (Transport)</td>
            <td style="text-align: right;">{pinfo.get('count', 0):,}</td>
            <td style="text-align: right;">{pinfo.get('percentage', 0.0):.1f}%</td>
        </tr>""")
    network_dict = protocols.get("network", {})
    for proto_name, pinfo in network_dict.items():
        proto_rows.append(f"""
        <tr>
            <td>{html.escape(proto_name)} (Network)</td>
            <td style="text-align: right;">{pinfo.get('count', 0):,}</td>
            <td style="text-align: right;">{pinfo.get('percentage', 0.0):.1f}%</td>
        </tr>""")
    proto_table_body = "".join(proto_rows) if proto_rows else "<tr><td colspan='3'>No protocol data recorded.</td></tr>"

    # Top Talkers Table
    talker_rows = []
    sources = top_talkers.get("sources", [])[:5]
    for s in sources:
        talker_rows.append(f"""
        <tr>
            <td><code>{html.escape(str(s.get('ip', '')))}</code></td>
            <td style="text-align: right;">{s.get('packets', 0):,}</td>
            <td style="text-align: right;">{s.get('bytes', 0):,} B</td>
        </tr>""")
    talker_table_body = "".join(talker_rows) if talker_rows else "<tr><td colspan='3'>No source talker data.</td></tr>"

    # Top Flows Table
    flow_rows = []
    for f in top_flows[:8]:
        state_badge = f"<span class='badge badge-state'>{html.escape(str(f.get('tcp_state', '')))}</span>"
        proto_tag = html.escape(str(f.get('transport_protocol', '')))
        flow_rows.append(f"""
        <tr>
            <td><code>{html.escape(str(f.get('flow_id', '')))}</code></td>
            <td><code>{html.escape(str(f.get('endpoint_a', '')))}</code> &harr; <code>{html.escape(str(f.get('endpoint_b', '')))}</code></td>
            <td>{proto_tag}</td>
            <td>{state_badge}</td>
            <td style="text-align: right;">{f.get('total_packets', 0):,}</td>
            <td style="text-align: right;">{f.get('total_bytes', 0):,} B</td>
            <td style="text-align: right;">{f.get('duration', 0.0):.2f}s</td>
        </tr>""")
    flow_table_body = "".join(flow_rows) if flow_rows else "<tr><td colspan='7'>No conversation flows identified.</td></tr>"

    # Alerts Table
    alert_cards = []
    if alerts:
        for alt in alerts:
            sev = alt.get("severity", "LOW").upper()
            sev_class = "badge-high" if sev == "HIGH" else ("badge-med" if sev == "MEDIUM" else "badge-low")
            title = html.escape(str(alt.get("alert_type", "Security Alert")))
            nature = html.escape(str(alt.get("classification_nature", "Heuristic Suspicion")))
            host = html.escape(str(alt.get("host", "N/A")))
            target = html.escape(str(alt.get("target", "N/A")))
            obs = html.escape(str(alt.get("observed_value") or alt.get("observed_metric") or "N/A"))
            thresh = html.escape(str(alt.get("threshold") or alt.get("configured_threshold") or "N/A"))
            window = html.escape(str(alt.get("time_window", "N/A")))
            expl = html.escape(str(alt.get("explanation", "")))
            refs = alt.get("packet_references", [])
            ref_str = ", ".join(f"#{r}" for r in refs[:10])
            if len(refs) > 10:
                ref_str += f" (+{len(refs) - 10} more)"

            alert_cards.append(f"""
            <div class="alert-item">
                <div class="alert-header">
                    <span class="badge {sev_class}">{sev}</span>
                    <strong class="alert-title">{title}</strong>
                    <span class="badge badge-nature">{nature}</span>
                </div>
                <div class="alert-grid">
                    <div><strong>Host:</strong> <code>{host}</code> &rarr; <code>{target}</code></div>
                    <div><strong>Observed:</strong> {obs}</div>
                    <div><strong>Threshold:</strong> {thresh}</div>
                    <div><strong>Window:</strong> {window}</div>
                </div>
                <p class="alert-expl">{expl}</p>
                {f'<div class="alert-refs"><strong>Supporting Frames:</strong> {ref_str}</div>' if refs else ''}
            </div>""")
        alerts_html = "".join(alert_cards)
    else:
        alerts_html = "<div class='empty-card'>No heuristic security anomalies or rate violations detected.</div>"

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope Traffic Intelligence Report — {clean_filename}</title>
    <style>
        :root {{
            --bg: #ffffff;
            --surface: #f8fafc;
            --surface-subtle: #f1f5f9;
            --text-main: #0f172a;
            --text-muted: #475569;
            --border: #e2e8f0;
            --primary: #2563eb;
            --high: #dc2626;
            --med: #d97706;
            --low: #2563eb;
            --success: #16a34a;
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: #0b0f19;
                --surface: #111827;
                --surface-subtle: #1f2937;
                --text-main: #f9fafb;
                --text-muted: #94a3b8;
                --border: rgba(255, 255, 255, 0.1);
                --primary: #3b82f6;
            }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 32px 24px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        header.report-header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .brand h1 {{
            font-size: 24px;
            color: var(--primary);
            letter-spacing: -0.5px;
        }}
        .brand p {{
            font-size: 13px;
            color: var(--text-muted);
        }}
        .meta-box {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }}
        .meta-box code {{
            background: var(--surface-subtle);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        section {{
            margin-bottom: 32px;
        }}
        h2 {{
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 12px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 6px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
        }}
        .kpi-title {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 600;
        }}
        .kpi-value {{
            font-size: 22px;
            font-weight: 700;
            color: var(--text-main);
            margin: 4px 0 2px 0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        .kpi-sub {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 8px;
        }}
        th, td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }}
        th {{
            background: var(--surface-subtle);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
        }}
        tr:last-child td {{ border-bottom: none; }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            background: var(--surface-subtle);
            padding: 2px 5px;
            border-radius: 4px;
        }}
        .badge {{
            display: inline-block;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-high {{ background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }}
        .badge-med {{ background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }}
        .badge-low {{ background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }}
        .badge-state {{ background: var(--surface-subtle); color: var(--text-muted); }}
        .badge-nature {{ background: var(--surface-subtle); color: var(--text-muted); font-size: 10px; }}
        .alert-item {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 12px;
        }}
        .alert-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .alert-title {{ font-size: 14px; color: var(--text-main); }}
        .alert-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 6px 16px;
            font-size: 12px;
            color: var(--text-muted);
            background: var(--surface-subtle);
            padding: 8px 12px;
            border-radius: 6px;
            margin-bottom: 8px;
        }}
        .alert-expl {{
            font-size: 12.5px;
            line-height: 1.4;
            color: var(--text-main);
            margin-bottom: 6px;
        }}
        .alert-refs {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        .empty-card {{
            background: var(--surface);
            border: 1px dashed var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }}
        .disclaimer-box {{
            background: var(--surface-subtle);
            border-left: 4px solid var(--primary);
            padding: 12px 16px;
            font-size: 12px;
            color: var(--text-muted);
            border-radius: 0 6px 6px 0;
            margin-top: 16px;
        }}
        @media print {{
            body {{ padding: 0; background: #fff; color: #000; }}
            .container {{ max-width: 100%; }}
            .kpi-card, table, .alert-item {{ border-color: #ccc; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Report Header -->
        <header class="report-header">
            <div class="brand">
                <h1>NetScope 3.0</h1>
                <p>Computer Networks Traffic Intelligence &amp; Protocol Verification Report</p>
            </div>
            <div class="meta-box">
                <div><strong>Capture:</strong> <code>{clean_filename}</code></div>
                <div><strong>Session ID:</strong> <code>{clean_capture_id}</code></div>
                <div><strong>Generated:</strong> {gen_time_utc}</div>
            </div>
        </header>

        <!-- Section 1: Methodology & Metrics Scorecard -->
        <section>
            <h2>1. Capture Overview &amp; Statistical Metrics</h2>
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-title">Total Packets</div>
                    <div class="kpi-value">{total_packets:,}</div>
                    <div class="kpi-sub">Frames Ingested</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Captured Volume</div>
                    <div class="kpi-value">{total_bytes:,} B</div>
                    <div class="kpi-sub">{total_bytes / 1024:.2f} KB wire bytes</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Capture Duration</div>
                    <div class="kpi-value">{duration:.3f} s</div>
                    <div class="kpi-sub">Timestamp span (t_max - t_min)</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Capture Rate</div>
                    <div class="kpi-value">{capture_pps:.1f} PPS</div>
                    <div class="kpi-sub">Packets per second</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Throughput</div>
                    <div class="kpi-value">{throughput_kbps:.2f} kbps</div>
                    <div class="kpi-sub">{throughput_mbps:.4f} Mbps</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Average Frame Size</div>
                    <div class="kpi-value">{avg_pkt_size:.1f} B</div>
                    <div class="kpi-sub">Bytes / packet</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Unique Endpoints</div>
                    <div class="kpi-value">{unique_hosts}</div>
                    <div class="kpi-sub">Distinct IP hosts</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Active 5-Tuple Flows</div>
                    <div class="kpi-value">{active_flows}</div>
                    <div class="kpi-sub">Bidirectional conversations</div>
                </div>
            </div>
            <div class="disclaimer-box">
                <strong>Academic Metric Definitions:</strong><br>
                &bull; <em>Capture Duration</em> is defined strictly as the time span between first and last recorded frame timestamps (t_max - t_min).<br>
                &bull; <em>Processing Rate ({proc_pps:,.1f} PPS in {proc_time:.4f}s)</em> reflects NetScope offline parsing throughput and is distinguished from on-wire packet arrival rate.<br>
                &bull; <em>Throughput</em> is computed as (total_bytes &times; 8) / duration.
            </div>
        </section>

        <!-- Section 2: Protocol Breakdown -->
        <section>
            <h2>2. Protocol Distribution</h2>
            <table>
                <thead>
                    <tr>
                        <th>Protocol Layer</th>
                        <th style="text-align: right;">Packet Count</th>
                        <th style="text-align: right;">Share (%)</th>
                    </tr>
                </thead>
                <tbody>
                    {proto_table_body}
                </tbody>
            </table>
        </section>

        <!-- Section 3: Top Talkers -->
        <section>
            <h2>3. Top Traffic Sources</h2>
            <table>
                <thead>
                    <tr>
                        <th>Source IP Address</th>
                        <th style="text-align: right;">Packets</th>
                        <th style="text-align: right;">Volume (Bytes)</th>
                    </tr>
                </thead>
                <tbody>
                    {talker_table_body}
                </tbody>
            </table>
        </section>

        <!-- Section 4: Conversation Flows -->
        <section>
            <h2>4. Significant Conversation Flows (5-Tuples)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Flow ID</th>
                        <th>Endpoints (A &harr; B)</th>
                        <th>Protocol</th>
                        <th>TCP State</th>
                        <th style="text-align: right;">Packets</th>
                        <th style="text-align: right;">Volume</th>
                        <th style="text-align: right;">Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {flow_table_body}
                </tbody>
            </table>
        </section>

        <!-- Section 5: Security Alerts -->
        <section>
            <h2>5. Heuristic Security Anomalies &amp; Threshold Alerts</h2>
            {alerts_html}
            <div class="disclaimer-box">
                <strong>Methodological Caution &amp; False-Positive Note:</strong><br>
                Heuristic alerts are statistical indicators generated by deterministic threshold rules (e.g. rapid SYN bursts, multi-port probes, packet rate spikes). 
                They do <strong>not</strong> constitute definitive evidence of malicious intrusions or compromise. Benign causes include multi-service API gateways, connection retry storms to unresponsive hosts, automated health probes, or network stress tests.
            </div>
        </section>

        <!-- Section 6: Operational Notes -->
        <section>
            <h2>6. Tooling &amp; Reproduction Notes</h2>
            <p style="font-size: 12.5px; color: var(--text-muted);">
                Generated autonomously by <strong>NetScope 3.0</strong> (Computer Networks Laboratory Mini-Project).
                Offline PCAP parsing performed with Scapy and Python 3.13. All metrics are computed deterministically without external API calls or CDN dependencies.
            </p>
        </section>
    </div>
</body>
</html>"""
    return html_template
