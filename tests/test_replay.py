"""
NetScope X Traffic Replay & Demonstration Lab Unit Tests
Verifies scenario packet generation, detector rule triggers, and player state transitions.
"""

from capture.replay_engine import ReplayEngine, SCENARIO_METADATA, build_scenario_packets
from analyzer.parser import parse_packet
from analytics.anomaly_detector import AnomalyDetector


def test_scenario_metadata_integrity():
    assert len(SCENARIO_METADATA) == 5
    required_keys = ["id", "name", "description", "expected_detection", "expected_severity", "category", "packet_count"]
    for sid, meta in SCENARIO_METADATA.items():
        for rk in required_keys:
            assert rk in meta, f"Missing {rk} in scenario {sid}"


def test_scenario_packet_builders():
    for sid in SCENARIO_METADATA.keys():
        pkts = build_scenario_packets(sid, base_time=1700000000.0)
        assert len(pkts) > 0, f"Scenario {sid} produced 0 packets"
        # Verify chronological order
        times = [float(p.time) for p in pkts]
        assert times == sorted(times), f"Packets in {sid} not strictly chronological"


def test_port_scan_scenario_triggers_anomaly():
    pkts = build_scenario_packets("port_scan", base_time=1700000000.0)
    detector = AnomalyDetector()

    triggered = []
    for idx, pkt in enumerate(pkts, start=1):
        rec = parse_packet(pkt, packet_id=idx)
        alerts = detector.evaluate_packet(rec)
        if alerts:
            triggered.extend(alerts)

    assert len(triggered) >= 1
    port_scan_alerts = [a for a in triggered if "Port Scan" in a["alert_type"] or "Multi-Port" in a["alert_type"]]
    assert len(port_scan_alerts) >= 1
    alert = port_scan_alerts[0]
    assert alert["host"] == "192.168.1.199"
    assert len(alert["packet_references"]) > 0


def test_syn_flood_scenario_triggers_anomaly():
    pkts = build_scenario_packets("syn_flood", base_time=1700000000.0)
    detector = AnomalyDetector()

    triggered = []
    for idx, pkt in enumerate(pkts, start=1):
        rec = parse_packet(pkt, packet_id=idx)
        alerts = detector.evaluate_packet(rec)
        if alerts:
            triggered.extend(alerts)

    assert len(triggered) >= 1
    syn_alerts = [a for a in triggered if "SYN Burst" in a["alert_type"]]
    assert len(syn_alerts) >= 1
    assert syn_alerts[0]["host"] == "10.0.0.88"


def test_benign_burst_scenario_does_not_trigger_syn_flood():
    pkts = build_scenario_packets("benign_burst", base_time=1700000000.0)
    detector = AnomalyDetector()

    triggered = []
    for idx, pkt in enumerate(pkts, start=1):
        rec = parse_packet(pkt, packet_id=idx)
        alerts = detector.evaluate_packet(rec)
        if alerts:
            triggered.extend(alerts)

    # Benign burst should NOT trigger SYN burst or Port scan because ACKs flow continuously
    syn_alerts = [a for a in triggered if "SYN Burst" in a["alert_type"]]
    assert len(syn_alerts) == 0


def test_replay_engine_lifecycle_states():
    engine = ReplayEngine()
    assert engine.get_status()["state"] == "IDLE"

    collected = []
    def callback(record):
        collected.append(record)

    # Instant speed
    status = engine.start("normal_traffic", packet_callback=callback, speed=0)
    assert status["state"] in ("RUNNING", "COMPLETED")

    # Wait briefly for thread to complete
    if engine._thread:
        engine._thread.join(timeout=2.0)

    final_st = engine.get_status()
    assert final_st["state"] == "COMPLETED"
    assert final_st["current_packet"] == len(collected)
    assert len(collected) > 0

    # Reset
    reset_st = engine.reset()
    assert reset_st["state"] == "IDLE"
    assert reset_st["current_packet"] == 0
