"""
NetScope REST API Integration Tests
Tests all endpoints: health, interfaces, upload, sample, stats, protocols,
timeline, top talkers, packet detail, and alerts.
"""

import io
import pytest


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json
    assert data["status"] == "ok"
    assert data["service"] == "NetScope"
    assert "version" in data
    assert "scapy_version" in data
    assert "live_capture_supported" in data


def test_api_interfaces(client):
    res = client.get("/api/interfaces")
    assert res.status_code == 200
    data = res.json
    assert "supported" in data
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)


def test_upload_invalid_extension(client):
    data = {"file": (io.BytesIO(b"fakecontent"), "malicious.exe")}
    res = client.post("/api/captures/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Invalid file extension" in res.json["error"]


def test_upload_missing_file(client):
    res = client.post("/api/captures/upload", data={}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "No file part" in res.json["error"]


def test_load_sample_and_inspect_metrics(client):
    # 1. Load sample capture
    res_load = client.post("/api/captures/load-sample")
    assert res_load.status_code == 200
    assert res_load.json["success"] is True

    # 2. Check stats endpoint
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json
    assert stats["total_packets"] == 60
    assert stats["total_bytes"] > 0
    assert stats["capture_duration_seconds"] > 0
    assert stats["unique_hosts"] > 0

    # 3. Check protocols endpoint
    res_proto = client.get("/api/protocols")
    assert res_proto.status_code == 200
    protos = res_proto.json
    assert "transport" in protos
    assert "TCP" in protos["transport"]
    assert "UDP" in protos["transport"]
    assert "network" in protos
    assert "IPv4" in protos["network"]
    assert "ARP" in protos["network"]

    # 4. Check traffic timeline
    res_time = client.get("/api/traffic-timeline")
    assert res_time.status_code == 200
    assert "timeline" in res_time.json
    assert len(res_time.json["timeline"]) > 0

    # 5. Check top talkers
    res_talk = client.get("/api/top-talkers")
    assert res_talk.status_code == 200
    talkers = res_talk.json
    assert "talkers" in talkers
    assert "top_ports" in talkers
    assert "top_flows" in talkers

    # 6. Check single packet detail
    res_detail = client.get("/api/packets/1")
    assert res_detail.status_code == 200
    pkt = res_detail.json
    assert pkt["packet_id"] == 1
    assert "details" in pkt
    assert "link_layer" in pkt["details"]

    # 7. Check 404 on nonexistent packet ID
    res_404 = client.get("/api/packets/99999")
    assert res_404.status_code == 404

    # 8. Check alerts endpoint
    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json["alerts"]
    assert len(alerts) > 0
    alert_types = [a["alert_type"] for a in alerts]
    assert any("SYN Flood" in t for t in alert_types)
    assert any("Port Scan" in t for t in alert_types)

    # 9. Check active capture metadata
    res_curr = client.get("/api/captures/status")
    assert res_curr.status_code == 200
    assert res_curr.json["filename"] == "sample_traffic.pcap"
    assert res_curr.json["packets_in_memory"] == 60


def test_alerts_config_api(client):
    # GET config
    res_get = client.get("/api/alerts/config")
    assert res_get.status_code == 200
    cfg = res_get.json["thresholds"]
    assert "syn_flood_threshold" in cfg
    assert "port_scan_threshold" in cfg
    assert "packet_rate_threshold" in cfg

    # POST config update
    res_post = client.post("/api/alerts/config", json={
        "syn_flood_threshold": 35,
        "port_scan_threshold": 12,
        "packet_rate_threshold": 300
    })
    assert res_post.status_code == 200
    assert res_post.json["success"] is True
    updated = res_post.json["thresholds"]
    assert updated["syn_flood_threshold"] == 35
    assert updated["port_scan_threshold"] == 12
    assert updated["packet_rate_threshold"] == 300

    # Invalid JSON or non-dict
    res_inv = client.post("/api/alerts/config", data="invalid string", content_type="application/json")
    assert res_inv.status_code == 400


def test_alert_fields_integrity_and_no_undefined(client):
    """Verify all alerts include valid observed_value and threshold strings (no 'undefined')."""
    res_load = client.post("/api/captures/load-sample")
    assert res_load.status_code == 200

    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json["alerts"]
    assert len(alerts) > 0

    for alert in alerts:
        # Check that observed_value exists and is a meaningful string
        assert "observed_value" in alert
        assert alert["observed_value"] is not None
        assert alert["observed_value"] != "undefined"
        assert len(str(alert["observed_value"]).strip()) > 0

        # Check threshold exists and is a meaningful string
        assert "threshold" in alert
        assert alert["threshold"] is not None
        assert alert["threshold"] != "undefined"
        assert len(str(alert["threshold"]).strip()) > 0

        # Check time window, host, classification
        assert "time_window" in alert
        assert alert["time_window"] is not None
        assert "host" in alert
        assert alert["host"] is not None
        assert "classification_nature" in alert


def test_flows_api_matches_stats_flow_count(client):
    """Verify /api/flows returns accurate counts matching /api/stats active_flows."""
    res_load = client.post("/api/captures/load-sample")
    assert res_load.status_code == 200

    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json
    expected_flows = stats.get("active_flows", 0)
    assert expected_flows > 0

    # Test default limit
    res_flows = client.get("/api/flows?limit=10")
    assert res_flows.status_code == 200
    flows_data = res_flows.json
    assert "flows" in flows_data
    assert "total_flows" in flows_data
    assert flows_data["total_flows"] == expected_flows
    assert len(flows_data["flows"]) <= 10

    # Validate first flow schema
    first_flow = flows_data["flows"][0]
    assert "flow_id" in first_flow
    assert "endpoint_a" in first_flow
    assert "endpoint_b" in first_flow
    assert "transport_protocol" in first_flow
    assert "total_packets" in first_flow
    assert "total_bytes" in first_flow
    assert "tcp_state" in first_flow


def test_empty_session_and_error_handling(client):
    """Verify clean responses and error codes when querying empty states or invalid resources."""
    # Reset active session
    res_reset = client.post("/api/captures/reset")
    assert res_reset.status_code == 200

    # 1. Stats on empty session
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    assert res_stats.json["total_packets"] == 0
    assert res_stats.json["active_flows"] == 0
    assert res_stats.json["capture_duration_seconds"] == 0.0

    # 2. Report export on empty session returns 400
    res_rep = client.get("/api/export/report")
    assert res_rep.status_code == 400
    assert "No capture session active" in res_rep.json["error"]

    # 3. Compare without active session returns 400
    res_cmp = client.post("/api/captures/compare", json={"compare_sample": True})
    assert res_cmp.status_code == 400
    assert "No active capture to compare against" in res_cmp.json["error"]

    # 4. Flow timeline 404
    res_flow_404 = client.get("/api/flows/nonexistent-flow/timeline")
    assert res_flow_404.status_code == 404

    # 5. Packet detail 404
    res_pkt_404 = client.get("/api/packets/123456")
    assert res_pkt_404.status_code == 404




