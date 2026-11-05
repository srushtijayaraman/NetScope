"""
NetScope X REST API Integration Tests
Tests /api/topology, /api/incidents, /api/replay, and /api/cases endpoints.
"""

import json
import pytest
from app import create_app
from config import TestConfig


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        yield client


def test_api_replay_scenarios_and_status(client):
    res = client.get("/api/replay/scenarios")
    assert res.status_code == 200
    data = res.get_json()
    assert "scenarios" in data
    assert len(data["scenarios"]) == 5

    res_st = client.get("/api/replay/status")
    assert res_st.status_code == 200
    assert "state" in res_st.get_json()


def test_api_replay_start_and_topology_integration(client):
    # Start normal traffic replay with instant speed
    res = client.post("/api/replay/start", json={"scenario_id": "normal_traffic", "speed": 0})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Check topology
    res_topo = client.get("/api/topology")
    assert res_topo.status_code == 200
    topo = res_topo.get_json()
    assert "nodes" in topo
    assert "edges" in topo
    assert len(topo["nodes"]) > 0

    # Stop and reset replay
    res_reset = client.post("/api/replay/reset")
    assert res_reset.status_code == 200


def test_api_port_scan_replay_generates_incidents(client):
    # Run port scan scenario instant
    res = client.post("/api/replay/start", json={"scenario_id": "port_scan", "speed": 0})
    assert res.status_code == 200

    # Query incidents
    res_inc = client.get("/api/incidents")
    assert res_inc.status_code == 200
    data = res_inc.get_json()
    assert "incidents" in data
    assert len(data["incidents"]) >= 1

    first_inc = data["incidents"][0]
    inc_id = first_inc["incident_id"]
    assert first_inc["category"] == "RECONNAISSANCE"
    assert "Port" in first_inc["rule_name"] or "Port" in first_inc["observed_value"]

    # Update incident status
    res_patch = client.patch(f"/api/incidents/{inc_id}", json={
        "status": "Investigating",
        "analyst_notes": "Assigned to SOC tier 2.",
    })
    assert res_patch.status_code == 200
    assert res_patch.get_json()["incident"]["status"] == "Investigating"

    # Fetch incident detail
    res_detail = client.get(f"/api/incidents/{inc_id}")
    assert res_detail.status_code == 200
    assert res_detail.get_json()["status"] == "Investigating"


def test_api_case_management_workflow(client):
    # Create Case
    res_create = client.post("/api/cases", json={
        "case_id": "CASE-TEST-100",
        "title": "Port Scan Analysis",
        "summary": "External IP reconnaissance detected.",
        "priority": "High",
        "analyst": "Alex",
        "artifacts": [
            {"artifact_type": "host", "artifact_id": "192.168.1.199"},
        ],
        "initial_note": "Case opened from incident report."
    })
    assert res_create.status_code == 201
    c = res_create.get_json()["case"]
    assert c["case_id"] == "CASE-TEST-100"
    assert len(c["artifacts"]) == 1
    assert len(c["notes"]) == 1

    # Add Note
    res_note = client.post("/api/cases/CASE-TEST-100/notes", json={
        "note": "Host quarantined from local VLAN.",
        "author": "NetAdmin",
    })
    assert res_note.status_code == 201

    # Attach Artifact
    res_art = client.post("/api/cases/CASE-TEST-100/artifacts", json={
        "artifact_type": "packet",
        "artifact_id": "12",
        "metadata": {"flags": ["SYN"]}
    })
    assert res_art.status_code == 201

    # Export Report
    res_rep = client.get("/api/cases/CASE-TEST-100/report")
    assert res_rep.status_code == 200
    assert b"Port Scan Analysis" in res_rep.data
    assert b"CASE-TEST-100" in res_rep.data
