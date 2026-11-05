"""
NetScope X Case Investigation & Forensic Reporting Subsystem
Manages structured cybersecurity investigation workbenches, analyst notes,
attached evidence artifacts (packets, flows, incidents, endpoints), and generates
standalone print-ready HTML forensic incident reports.
"""

import html
import time
from datetime import datetime, timezone


def generate_case_html_report(case: dict, capture_meta: dict = None) -> str:
    """
    Renders a standalone, print-ready, zero-CDN HTML case report.
    Applies strict XSS escaping via html.escape.
    """
    capture_meta = capture_meta or {}
    case_id = html.escape(str(case.get("case_id", "CASE-UNKNOWN")))
    title = html.escape(str(case.get("title", "Network Security Investigation")))
    summary = html.escape(str(case.get("summary", "No executive summary provided.")))
    priority = html.escape(str(case.get("priority", "Medium")))
    status = html.escape(str(case.get("status", "Open")))
    analyst = html.escape(str(case.get("analyst", "SecOps Analyst")))
    created_at = html.escape(str(case.get("created_at", "")))
    updated_at = html.escape(str(case.get("updated_at", "")))

    notes = case.get("notes", [])
    artifacts = case.get("artifacts", [])

    priority_badge_class = {
        "High": "badge-danger",
        "Medium": "badge-warning",
        "Low": "badge-info"
    }.get(case.get("priority"), "badge-info")

    status_badge_class = {
        "Open": "badge-primary",
        "In Progress": "badge-warning",
        "Closed": "badge-success"
    }.get(case.get("status"), "badge-primary")

    # Format Notes
    notes_html = ""
    if notes:
        for n in notes:
            n_author = html.escape(str(n.get("author", "Analyst")))
            n_time = html.escape(str(n.get("created_at", "")))
            n_text = html.escape(str(n.get("note", ""))).replace("\n", "<br>")
            notes_html += f"""
            <div class="note-card">
                <div class="note-meta">
                    <strong>{n_author}</strong> &bull; <span>{n_time}</span>
                </div>
                <div class="note-body">{n_text}</div>
            </div>
            """
    else:
        notes_html = "<p class='empty-text'>No investigation notes recorded yet.</p>"

    # Format Artifacts
    artifacts_html = ""
    if artifacts:
        artifacts_html = """
        <table class="report-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Identifier</th>
                    <th>Forensic Context / Metadata</th>
                    <th>Attached At</th>
                </tr>
            </thead>
            <tbody>
        """
        for art in artifacts:
            atype = html.escape(str(art.get("artifact_type", "")).upper())
            aid = html.escape(str(art.get("artifact_id", "")))
            atime = html.escape(str(art.get("created_at", "")))
            meta = art.get("metadata", {})
            meta_str = ", ".join([f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in meta.items()]) if meta else "Direct Reference"
            artifacts_html += f"""
                <tr>
                    <td><span class="badge badge-outline">{atype}</span></td>
                    <td><strong>{aid}</strong></td>
                    <td>{meta_str}</td>
                    <td>{atime}</td>
                </tr>
            """
        artifacts_html += "</tbody></table>"
    else:
        artifacts_html = "<p class='empty-text'>No evidence artifacts attached to this case.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope X Forensic Case Report | {case_id}</title>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --surface-color: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #d97706;
            --success-color: #16a34a;
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-color: #0b0f19;
                --surface-color: #111827;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
                --border-color: #1f2937;
                --primary-color: #3b82f6;
            }}
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 900px;
            margin: 0 auto;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .header-title h1 {{
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 6px;
            color: var(--text-main);
        }}
        .header-title p {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .case-id-badge {{
            font-family: monospace;
            font-size: 16px;
            font-weight: 700;
            background: var(--border-color);
            padding: 6px 12px;
            border-radius: 6px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
            padding: 16px;
            background: var(--bg-color);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .meta-item label {{
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}
        .meta-item span {{
            font-size: 14px;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-danger {{ background: #fee2e2; color: #991b1b; }}
        .badge-warning {{ background: #fef3c7; color: #92400e; }}
        .badge-info {{ background: #e0f2fe; color: #075985; }}
        .badge-primary {{ background: #dbeafe; color: #1e40af; }}
        .badge-success {{ background: #dcfce7; color: #166534; }}
        .badge-outline {{ border: 1px solid var(--border-color); color: var(--text-muted); font-size: 11px; }}
        .section {{ margin-bottom: 30px; }}
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 12px;
            padding-bottom: 6px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .summary-box {{
            padding: 16px;
            background: var(--bg-color);
            border-left: 4px solid var(--primary-color);
            border-radius: 4px;
            font-size: 14px;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .report-table th, .report-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }}
        .report-table th {{
            background: var(--bg-color);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
        }}
        .note-card {{
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 14px;
            margin-bottom: 12px;
            background: var(--bg-color);
        }}
        .note-meta {{
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .note-body {{
            font-size: 14px;
            color: var(--text-main);
        }}
        .empty-text {{
            font-size: 13px;
            color: var(--text-muted);
            font-style: italic;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
        }}
        @media print {{
            body {{ background: #fff; padding: 0; color: #000; }}
            .report-container {{ border: none; box-shadow: none; padding: 0; width: 100%; max-width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="header">
            <div class="header-title">
                <h1>NetScope X &bull; Case Investigation Report</h1>
                <p>{title}</p>
            </div>
            <div class="case-id-badge">{case_id}</div>
        </header>

        <section class="meta-grid">
            <div class="meta-item">
                <label>Investigation Status</label>
                <span><span class="badge {status_badge_class}">{status}</span></span>
            </div>
            <div class="meta-item">
                <label>Priority</label>
                <span><span class="badge {priority_badge_class}">{priority}</span></span>
            </div>
            <div class="meta-item">
                <label>Lead Analyst</label>
                <span>{analyst}</span>
            </div>
            <div class="meta-item">
                <label>Last Updated</label>
                <span>{updated_at[:19] if len(updated_at) >= 19 else updated_at}</span>
            </div>
        </section>

        <section class="section">
            <h2 class="section-title">1. Executive Investigation Summary</h2>
            <div class="summary-box">
                {summary}
            </div>
        </section>

        <section class="section">
            <h2 class="section-title">2. Attached Evidence & Artifact References ({len(artifacts)})</h2>
            {artifacts_html}
        </section>

        <section class="section">
            <h2 class="section-title">3. Forensic Timeline & Analyst Findings ({len(notes)})</h2>
            {notes_html}
        </section>

        <footer class="footer">
            <span>Generated autonomously by <strong>NetScope X Platform</strong></span>
            <span>Created: {created_at[:19] if len(created_at) >= 19 else created_at} UTC</span>
        </footer>
    </div>
</body>
</html>
"""
    return html_content
