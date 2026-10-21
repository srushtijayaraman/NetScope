"""
NetScope Report Generator Tests
Validates:
- Self-contained HTML report generation with all metric sections
- Safe HTML escaping of arbitrary or hostile user inputs (preventing XSS)
- Report download API (/api/export/report)
- 400 error guard when generating report on empty session
"""

import html
import pytest
from analytics.report_generator import generate_html_report
from routes.api import reset_active_session


def test_html_report_generation_structure():
    summary = {
        "total_packets": 100,
        "total_bytes": 15000,
        "capture_duration_seconds": 2.5,
        "processing_time_seconds": 0.05,
        "capture_pps": 40.0,
        "processing_pps": 2000.0,
        "average_packet_size_bytes": 150.0,
        "throughput_kbps": 48.0,
        "throughput_mbps": 0.048,
        "unique_hosts": 4,
        "active_flows": 2,
        "parsing_errors": 0,
    }
    protocols = {
        "transport": {"TCP": {"count": 80, "percentage": 80.0}, "UDP": {"count": 20, "percentage": 20.0}},
        "network": {"IPv4": {"count": 100, "percentage": 100.0}},
    }
    top_talkers = {
        "sources": [{"ip": "192.168.1.10", "packets": 50, "bytes": 7500}],
    }
    top_flows = [
        {
            "flow_id": "flow-1",
            "endpoint_a": "192.168.1.10:12345",
            "endpoint_b": "93.184.216.34:80",
            "transport_protocol": "TCP",
            "tcp_state": "ESTABLISHED",
            "total_packets": 80,
            "total_bytes": 12000,
            "duration": 2.0,
        }
    ]
    alerts = [
        {
            "alert_type": "Heuristic: Suspicious SYN Burst",
            "classification_nature": "Heuristic Suspicion",
            "severity": "HIGH",
            "host": "192.168.1.10",
            "target": "93.184.216.34",
            "observed_value": "20 SYNs",
            "threshold": "15 SYNs",
            "time_window": "5.0s window",
            "explanation": "Observed rapid SYN frames.",
            "packet_references": [1, 2, 3],
        }
    ]

    report_html = generate_html_report(
        summary, protocols, top_talkers, top_flows, alerts, filename="test_capture.pcap", capture_id="test-1"
    )

    assert "<!DOCTYPE html>" in report_html
    assert "NetScope 3.0" in report_html
    assert "test_capture.pcap" in report_html
    assert "100" in report_html
    assert "15,000 B" in report_html
    assert "48.00 kbps" in report_html
    assert "TCP" in report_html
    assert "Suspicious SYN Burst" in report_html
    assert "Methodological Caution &amp; False-Positive Note" in report_html


def test_html_report_xss_escaping():
    hostile_filename = "<script>alert('pwned')</script>.pcap"
    hostile_ip = "<img src=x onerror=alert(1)>"
    summary = {
        "total_packets": 1,
        "total_bytes": 100,
        "capture_duration_seconds": 1.0,
        "processing_time_seconds": 0.01,
        "capture_pps": 1.0,
        "processing_pps": 100.0,
        "average_packet_size_bytes": 100.0,
        "throughput_kbps": 0.8,
        "throughput_mbps": 0.0008,
        "unique_hosts": 1,
        "active_flows": 1,
        "parsing_errors": 0,
    }
    protocols = {"transport": {}, "network": {}}
    top_talkers = {"sources": [{"ip": hostile_ip, "packets": 1, "bytes": 100}]}
    top_flows = []
    alerts = []

    report_html = generate_html_report(
        summary, protocols, top_talkers, top_flows, alerts, filename=hostile_filename, capture_id="xss-test"
    )

    # The raw unescaped script tag MUST NOT appear
    assert "<script>alert('pwned')</script>" not in report_html
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in report_html
    assert "<img src=x" not in report_html
    assert "&lt;img src=x" in report_html


def test_report_api_endpoint(client):
    reset_active_session("", "", "none")
    # Empty capture should return 400
    res_empty = client.get("/api/export/report")
    assert res_empty.status_code == 400

    # Load sample and export report
    client.post("/api/captures/load-sample")
    res_rep = client.get("/api/export/report")
    assert res_rep.status_code == 200
    assert "text/html" in res_rep.content_type
    assert "NetScope 3.0" in res_rep.text
    assert "sample_traffic.pcap" in res_rep.text

    # Test download parameter
    res_down = client.get("/api/export/report?download=1")
    assert res_down.status_code == 200
    assert "attachment;" in res_down.headers.get("Content-Disposition", "")
