"""
NetScope Lifecycle and Queue Stress Tests
Validates capture lifecycle: start, stop, unsupported backend reporting,
session replacement, queue overflow accounting, and graceful shutdown.
"""

import queue
import pytest
from capture.live_capture import LiveCaptureManager


def test_live_capture_manager_unsupported_on_current_host():
    """
    On a Windows machine without Npcap installed, LiveCaptureManager
    must gracefully report UNSUPPORTED_BACKEND and provide the remediation solution.
    """
    manager = LiveCaptureManager(queue_size=10)
    res = manager.start_capture(interface="dummy0")
    
    # Should fail safely without crashing
    assert res["success"] is False
    assert manager.status in ("UNSUPPORTED_BACKEND", "ERROR")
    assert "npcap" in res["error"].lower() or "not installed" in res["error"].lower() or "interface" in res["error"].lower()


def test_queue_overflow_and_drop_accounting():
    """
    Verifies that when packet arrival exceeds queue capacity,
    the enqueue method increments queue_drops without blocking or raising.
    """
    manager = LiveCaptureManager(queue_size=3)
    
    # Simulate enqueuing 5 packets into a queue of size 3
    for i in range(5):
        manager._enqueue_packet(f"dummy_packet_{i}")

    assert manager.packets_captured == 5
    # 3 should be stored in queue, 2 dropped due to queue full
    assert manager.queue_drops == 2
    assert manager.packet_queue.qsize() == 3


def test_stop_capture_idempotent():
    manager = LiveCaptureManager()
    res = manager.stop_capture()
    assert res["success"] is True
    assert "not running" in res["message"].lower()


def test_session_replacement(client):
    # Load first sample
    res1 = client.post("/api/captures/load-sample")
    assert res1.status_code == 200
    cap1_id = res1.json["capture_id"]

    # Verify status
    st1 = client.get("/api/captures/status").json
    assert st1["capture_id"] == cap1_id
    assert st1["packets_in_memory"] == 60

    # Load second sample (replaces session)
    res2 = client.post("/api/captures/load-sample")
    assert res2.status_code == 200
    cap2_id = res2.json["capture_id"]
    assert cap2_id != cap1_id

    # Verify session replaced without mixing packets
    st2 = client.get("/api/captures/status").json
    assert st2["capture_id"] == cap2_id
    assert st2["packets_in_memory"] == 60
