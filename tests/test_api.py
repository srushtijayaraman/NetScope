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


