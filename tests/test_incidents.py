"""
NetScope X Security Incident Correlator Unit Tests
Verifies alert-to-incident correlation, deduplication within window,
persistence in SQLite, and status/notes updates.
"""

import os
import tempfile
from analytics.incident_correlator import IncidentCorrelator
from storage.database import DatabaseManager


def test_incident_correlation_and_deduplication():
    correlator = IncidentCorrelator(correlation_window_sec=10.0)

    alert_1 = {
        "alert_type": "Heuristic: Suspicious SYN Burst (Possible SYN Flood)",
        "host": "192.168.1.100",
        "target": "10.0.0.50",
        "timestamp": 1700000000.0,
        "observed_value": "25 standalone SYNs",
        "configured_threshold": "20 SYNs in 5s",
        "explanation": "High frequency of unacknowledged SYN packets.",
        "packet_references": [1, 2, 3, 4],
    }

    inc_1 = correlator.correlate_alert(alert_1, capture_id="test-cap")
    assert inc_1["incident_id"] == "INC-0001"
    assert inc_1["category"] == "DENIAL_OF_SERVICE"
    assert inc_1["severity"] == "HIGH"
    assert inc_1["hit_count"] == 1
    assert inc_1["status"] == "New"
    assert "backlog" in inc_1["severity_rationale"].lower()
    assert inc_1["evidence"]["packet_ids"] == [1, 2, 3, 4]

    # Alert 2 (Within 10-second window, same host & category -> should merge)
    alert_2 = {
        "alert_type": "Heuristic: Suspicious SYN Burst (Possible SYN Flood)",
        "host": "192.168.1.100",
        "target": "10.0.0.50",
        "timestamp": 1700000005.0,
        "observed_value": "35 standalone SYNs",
        "configured_threshold": "20 SYNs in 5s",
        "packet_references": [5, 6, 7],
    }

    inc_2 = correlator.correlate_alert(alert_2, capture_id="test-cap")
    assert inc_2["incident_id"] == "INC-0001"  # Same incident!
    assert inc_2["hit_count"] == 2
    assert inc_2["last_seen"] == 1700000005.0
    assert inc_2["duration_sec"] == 5.0
    assert inc_2["evidence"]["packet_ids"] == [1, 2, 3, 4, 5, 6, 7]


def test_incident_status_update_and_persistence():
    temp_db_path = os.path.join(tempfile.gettempdir(), f"netscope_inc_test_{os.getpid()}.db")
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)

    try:
        db = DatabaseManager(temp_db_path)
        correlator = IncidentCorrelator()

        alert = {
            "alert_type": "Heuristic: Potential Port Scan / Multi-Port Probe",
            "host": "10.0.0.99",
            "target": "192.168.1.1",
            "timestamp": 1700000010.0,
            "observed_value": "18 distinct ports probed",
            "configured_threshold": "15 ports in 5s",
            "explanation": "Multiple ports probed sequentially.",
            "packet_references": [10, 11, 12],
        }

        inc = correlator.correlate_alert(alert, capture_id="cap-1")
        saved = db.upsert_incident(inc)
        assert saved["incident_id"] == inc["incident_id"]
        assert saved["category"] == "RECONNAISSANCE"
        assert saved["status"] == "New"

        # Update status and notes
        correlator.update_status(inc["incident_id"], "Investigating", notes="Confirmed internal vulnerability scan.")
        db.update_incident_status(inc["incident_id"], "Investigating", notes="Confirmed internal vulnerability scan.")

        fetched = db.get_incident(inc["incident_id"])
        assert fetched["status"] == "Investigating"
        assert "Confirmed internal" in fetched["analyst_notes"]

        # Fetch list
        all_incidents = db.get_incidents()
        assert len(all_incidents) == 1
        assert all_incidents[0]["incident_id"] == inc["incident_id"]

    finally:
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
