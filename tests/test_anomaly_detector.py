"""
NetScope Anomaly Detector Unit Tests (Enhanced)
Validates:
1. Normal benign traffic (handshakes, single-port web browsing) -> zero false-positive alerts.
2. Suspicious traffic (rapid SYN bursts, multi-port scans) -> correctly flagged with supporting packet references.
3. False-positive edge cases (e.g. repeated connections to a single web port).
4. Threshold dynamic reconfiguration and cooldown deduplication.
"""

import pytest
from analytics.anomaly_detector import AnomalyDetector


class MockConfig:
    PACKET_RATE_THRESHOLD = 50
    BYTE_RATE_THRESHOLD = 100_000
    SYN_FLOOD_THRESHOLD = 5
    PORT_SCAN_THRESHOLD = 4
    HOST_VOLUME_RATIO_THRESHOLD = 0.5
    ANOMALY_COOLDOWN_SECONDS = 5


def test_normal_benign_traffic_no_alerts():
    """
    Legitimate web traffic (normal 3-way handshakes, HTTP GET, 200 OK)
    must NOT trigger any anomaly alerts.
    """
    detector = AnomalyDetector(MockConfig)
    
    # 3 legitimate completed handshakes to port 80
    base_t = 100.0
    packets = [
        {"source_ip": "192.168.1.10", "destination_ip": "93.184.216.34", "transport_protocol": "TCP", "source_port": 50001, "destination_port": 80, "tcp_flags": ["SYN"], "timestamp": base_t, "packet_id": 1},
        {"source_ip": "93.184.216.34", "destination_ip": "192.168.1.10", "transport_protocol": "TCP", "source_port": 80, "destination_port": 50001, "tcp_flags": ["SYN", "ACK"], "timestamp": base_t + 0.02, "packet_id": 2},
        {"source_ip": "192.168.1.10", "destination_ip": "93.184.216.34", "transport_protocol": "TCP", "source_port": 50001, "destination_port": 80, "tcp_flags": ["ACK"], "timestamp": base_t + 0.03, "packet_id": 3},
        {"source_ip": "192.168.1.10", "destination_ip": "93.184.216.34", "transport_protocol": "TCP", "source_port": 50001, "destination_port": 80, "tcp_flags": ["PA"], "timestamp": base_t + 0.05, "packet_id": 4},
    ]

    for p in packets:
        alerts = detector.evaluate_packet(p)
        assert len(alerts) == 0, f"False positive generated on benign packet {p}"

    assert len(detector.get_all_alerts()) == 0


def test_false_positive_single_port_repeated_requests():
    """
    A client issuing 10 consecutive HTTP requests to a single destination port (80)
    must NOT trigger a port scan alert, because the number of distinct queried ports is 1.
    """
    detector = AnomalyDetector(MockConfig)
    base_t = 200.0

    for i in range(10):
        alerts = detector.evaluate_packet({
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "transport_protocol": "TCP",
            "source_port": 40000 + i,
            "destination_port": 80,  # All to port 80
            "tcp_flags": ["PA"],
            "timestamp": base_t + (i * 0.1),
            "packet_id": 100 + i,
        })
        assert len(alerts) == 0

    assert len(detector.get_all_alerts()) == 0


def test_syn_flood_rule_with_packet_references():
    detector = AnomalyDetector(MockConfig)
    
    # 4 SYNs (below threshold of 5)
    for i in range(4):
        alerts = detector.evaluate_packet({
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 100.0 + (i * 0.1),
            "packet_id": i + 1,
        })
        assert len(alerts) == 0

    # 5th SYN triggers threshold
    alerts = detector.evaluate_packet({
        "source_ip": "192.168.1.99",
        "destination_ip": "10.0.0.1",
        "transport_protocol": "TCP",
        "tcp_flags": ["SYN"],
        "timestamp": 100.5,
        "packet_id": 5,
    })
    assert len(alerts) == 1
    alt = alerts[0]
    assert "SYN Burst" in alt["alert_type"]
    assert alt["host"] == "192.168.1.99"
    assert alt["severity"] == "HIGH"
    assert alt["packet_references"] == [1, 2, 3, 4, 5]
    assert alt["classification_nature"] == "Heuristic Suspicion (Unconfirmed)"


def test_syn_flood_cooldown():
    detector = AnomalyDetector(MockConfig)
    
    for i in range(5):
        detector.evaluate_packet({
            "source_ip": "10.0.0.99",
            "destination_ip": "1.1.1.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 10.0 + (i * 0.1),
            "packet_id": 20 + i,
        })
    assert len(detector.alerts) == 1

    # Immediate 6th SYN within cooldown must be suppressed
    more_alerts = detector.evaluate_packet({
        "source_ip": "10.0.0.99",
        "destination_ip": "1.1.1.1",
        "transport_protocol": "TCP",
        "tcp_flags": ["SYN"],
        "timestamp": 10.6,
        "packet_id": 25,
    })
    assert len(more_alerts) == 0


def test_port_scan_rule_triggered_with_references():
    detector = AnomalyDetector(MockConfig)
    
    # Query 4 distinct destination ports (threshold is 4)
    for p in range(80, 84):
        alerts = detector.evaluate_packet({
            "source_ip": "192.168.1.88",
            "destination_ip": "10.0.0.5",
            "transport_protocol": "TCP",
            "destination_port": p,
            "timestamp": 200.0 + ((p - 80) * 0.2),
            "packet_id": 50 + (p - 80),
        })

    assert len(detector.alerts) == 1
    alt = detector.alerts[0]
    assert "Multi-Port Probe" in alt["alert_type"]
    assert alt["host"] == "192.168.1.88"
    assert alt["packet_references"] == [50, 51, 52, 53]


def test_dynamic_threshold_reconfiguration():
    detector = AnomalyDetector(MockConfig)
    orig_thresholds = detector.get_thresholds()
    assert orig_thresholds["syn_flood_threshold"] == 5

    # Update threshold to 8
    updated = detector.update_thresholds({"syn_flood_threshold": 8})
    assert updated["syn_flood_threshold"] == 8

    # 5 SYNs should no longer trigger
    for i in range(5):
        detector.evaluate_packet({
            "source_ip": "10.0.0.77",
            "destination_ip": "1.1.1.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 300.0 + (i * 0.1),
            "packet_id": 300 + i,
        })
    assert len(detector.alerts) == 0

    # 3 more SYNs (total 8) triggers with new threshold
    for i in range(5, 8):
        detector.evaluate_packet({
            "source_ip": "10.0.0.77",
            "destination_ip": "1.1.1.1",
            "transport_protocol": "TCP",
            "tcp_flags": ["SYN"],
            "timestamp": 300.0 + (i * 0.1),
            "packet_id": 300 + i,
        })
    assert len(detector.alerts) == 1


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
    assert any("Dominant Traffic Host" in a["alert_type"] for a in alerts)
    dom_alert = [a for a in alerts if "Dominant" in a["alert_type"]][0]
    assert dom_alert["classification_nature"] == "Observable Traffic Fact"
