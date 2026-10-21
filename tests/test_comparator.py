"""
NetScope Capture Comparator Tests
Validates:
- Standalone isolated PCAP processing without mutating session state
- Volume and rate metric deltas (packets, bytes, PPS, throughput)
- Zero-denominator guard when comparing empty or 0-rate metrics
- Methodological disparate duration warning detection
- Protocol distribution shifts
- Comparison API endpoint (/api/captures/compare)
"""

import io
import os
import pytest
from analytics.capture_comparator import (
    analyze_standalone_pcap,
    compute_metric_diff,
    compare_captures,
)


def test_compute_metric_diff_zero_guard():
    # Both zero
    res1 = compute_metric_diff(0, 0)
    assert res1["diff"] == 0
    assert res1["pct_change"] == 0.0

    # From 0 to positive
    res2 = compute_metric_diff(0, 50)
    assert res2["diff"] == 50
    assert res2["pct_change"] == 100.0

    # Normal delta
    res3 = compute_metric_diff(100, 150)
    assert res3["diff"] == 50
    assert res3["pct_change"] == 50.0

    # Reduction
    res4 = compute_metric_diff(200, 100)
    assert res4["diff"] == -100
    assert res4["pct_change"] == -50.0


def test_standalone_pcap_analysis():
    data = analyze_standalone_pcap("data/sample_traffic.pcap")
    assert "summary" in data
    assert data["summary"]["total_packets"] == 60
    assert data["summary"]["total_bytes"] > 0
    assert "protocols" in data
    assert "TCP" in data["protocols"]["transport"]
    assert "alerts" in data
    assert len(data["alerts"]) > 0


def test_compare_identical_captures():
    data_a = analyze_standalone_pcap("data/sample_traffic.pcap")
    data_b = analyze_standalone_pcap("data/sample_traffic.pcap")

    comp = compare_captures(data_a, data_b, "Run 1", "Run 2")
    assert comp["metrics"]["total_packets"]["diff"] == 0
    assert comp["metrics"]["total_packets"]["pct_change"] == 0.0
    assert comp["metrics"]["total_bytes"]["diff"] == 0
    assert comp["duration_warning"] is None


def test_disparate_duration_warning():
    # Synthetic summaries with 1.0s vs 20.0s durations (ratio 20x)
    data_a = {
        "summary": {"total_packets": 10, "total_bytes": 1000, "capture_duration_seconds": 1.0},
        "protocols": {},
        "alerts": [],
    }
    data_b = {
        "summary": {"total_packets": 200, "total_bytes": 20000, "capture_duration_seconds": 20.0},
        "protocols": {},
        "alerts": [],
    }
    comp = compare_captures(data_a, data_b)
    assert comp["duration_warning"] is not None
    assert "Observation spans differ significantly" in comp["duration_warning"]


def test_compare_api_endpoint(client):
    # 1. Load active capture
    client.post("/api/captures/load-sample")

    # 2. Compare active session with sample fixture
    res_cmp = client.post("/api/captures/compare", data={"compare_sample": "true"})
    assert res_cmp.status_code == 200
    body = res_cmp.json
    assert "capture_a" in body
    assert "capture_b" in body
    assert "metrics" in body
    assert "protocol_shifts" in body
    assert "alerts_comparison" in body

    # 3. Compare without any second file or active capture should reject
    client_empty = client
    # Test invalid call without second file
    res_bad = client_empty.post("/api/captures/compare", data={})
    assert res_bad.status_code == 400
