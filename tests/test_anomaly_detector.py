"""
NetScope Anomaly Detector Unit Tests
Validates detection logic for SYN floods, port scans, packet rate spikes,
and dominant traffic hosts with explainable evidence and cooldown enforcement.
"""

from analytics.anomaly_detector import AnomalyDetector


class MockConfig:
    PACKET_RATE_THRESHOLD = 50
    BYTE_RATE_THRESHOLD = 100_000
    SYN_FLOOD_THRESHOLD = 5
    PORT_SCAN_THRESHOLD = 4
    HOST_VOLUME_RATIO_THRESHOLD = 0.5
    ANOMALY_COOLDOWN_SECONDS = 5


def test_syn_flood_rule_triggered():
    detector = AnomalyDetector(MockConfig)
    
    # Send 4 SYNs (below threshold of 5)
    for i in range(4):
        alerts = detector.evaluate_packet({
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 100.0 + (i * 0.1),
        })
        assert len(alerts) == 0

    # 5th SYN triggers threshold
    alerts = detector.evaluate_packet({
        "source_ip": "192.168.1.99",
        "destination_ip": "10.0.0.1",
        "transport_protocol": "TCP",
        "tcp_flags": ["SYN"],
        "timestamp": 100.5,
    })
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SYN Flood Warning"
    assert alerts[0]["host"] == "192.168.1.99"
    assert alerts[0]["severity"] == "HIGH"


def test_syn_flood_cooldown():
    detector = AnomalyDetector(MockConfig)
    
    for i in range(5):
        detector.evaluate_packet({
            "source_ip": "10.0.0.99",
            "destination_ip": "1.1.1.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 10.0 + (i * 0.1),
        })
    assert len(detector.alerts) == 1

    # Immediate 6th SYN should not generate second alert due to cooldown
    more_alerts = detector.evaluate_packet({
        "source_ip": "10.0.0.99",
        "destination_ip": "1.1.1.1",
        "transport_protocol": "TCP",
        "tcp_flags": ["SYN"],
        "timestamp": 10.6,
    })
    assert len(more_alerts) == 0


def test_port_scan_rule_triggered():
    detector = AnomalyDetector(MockConfig)
    
    # Query 4 distinct destination ports (threshold is 4)
    for p in range(80, 84):
        alerts = detector.evaluate_packet({
            "source_ip": "192.168.1.88",
            "destination_ip": "10.0.0.5",
            "transport_protocol": "TCP",
            "destination_port": p,
            "timestamp": 200.0 + ((p - 80) * 0.2),
        })

    assert len(detector.alerts) == 1
    assert detector.alerts[0]["alert_type"] == "Port Scan Detected"
    assert detector.alerts[0]["host"] == "192.168.1.88"


def test_batch_dominant_host_rule():
    detector = AnomalyDetector(MockConfig)
    
    summary = {"total_packets": 100, "capture_duration_seconds": 10.0}
    timeline = [{"timestamp": 10.0, "pps": 10, "kbps": 20}]
    top_talkers = {
        "sources": [
            {"ip": "192.168.1.200", "packets": 80, "bytes": 8000},
            {"ip": "192.168.1.10", "packets": 20, "bytes": 2000},
        ]
    }

    alerts = detector.evaluate_batch_statistics(summary, timeline, top_talkers)
    assert any(a["alert_type"] == "Dominant Traffic Host" for a in alerts)
