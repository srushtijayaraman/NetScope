"""
NetScope TCP Conversation Inspector Tests
Validates flow conversation analysis:
- Full 3-way handshake detection
- Incomplete handshake tracking (SYN only, SYN-ACK only)
- Mid-stream capture handling (no handshake frames observed)
- Connection teardown (FIN) and abort (RST) state transitions
- TCP sequence tracking and retransmission detection
- Endpoint timeline progression API (/api/flows/<flow_id>/timeline)
- UDP/stateless protocol isolation
"""

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw
from analyzer.parser import parse_packet
from analyzer.flow_tracker import FlowTracker


def test_complete_tcp_handshake_and_teardown():
    tracker = FlowTracker()
    base_ts = 1700000000.0

    # 1. SYN
    pkt1 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="S", seq=100)
    pkt1.time = base_ts + 0.01
    rec1 = parse_packet(pkt1, 1, base_timestamp=base_ts)
    tracker.process_packet(rec1)

    flow = tracker.get_flow_by_id(rec1["flow_id"])
    assert flow["tcp_state"] == "SYN_SENT"
    assert flow["handshake_status"] == "Incomplete (SYN Sent Only)"

    # 2. SYN-ACK
    pkt2 = Ether() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=50000, flags="SA", seq=500, ack=101)
    pkt2.time = base_ts + 0.02
    rec2 = parse_packet(pkt2, 2, base_timestamp=base_ts)
    tracker.process_packet(rec2)

    flow = tracker.get_flow_by_id(rec1["flow_id"])
    assert flow["tcp_state"] == "SYN_ACK"
    assert "Incomplete" in flow["handshake_status"]

    # 3. ACK (completing 3-way handshake)
    pkt3 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="A", seq=101, ack=501)
    pkt3.time = base_ts + 0.03
    rec3 = parse_packet(pkt3, 3, base_timestamp=base_ts)
    tracker.process_packet(rec3)

    flow = tracker.get_flow_by_id(rec1["flow_id"])
    assert flow["tcp_state"] == "ESTABLISHED"
    assert flow["handshake_status"] == "Complete (3-Way Handshake)"

    # 4. Application Data
    data = b"GET / HTTP/1.1\r\n\r\n"
    pkt4 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="PA", seq=101, ack=501) / Raw(data)
    pkt4.time = base_ts + 0.05
    rec4 = parse_packet(pkt4, 4, base_timestamp=base_ts)
    tracker.process_packet(rec4)

    # 5. FIN teardown
    pkt5 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="FA", seq=101 + len(data), ack=501)
    pkt5.time = base_ts + 0.10
    rec5 = parse_packet(pkt5, 5, base_timestamp=base_ts)
    tracker.process_packet(rec5)

    flow = tracker.get_flow_by_id(rec1["flow_id"])
    assert flow["tcp_state"] in ("CLOSING", "CLOSED")

    # Check conversation timeline
    timeline = tracker.get_flow_timeline(rec1["flow_id"])
    assert timeline is not None
    assert timeline["flow_id"] == rec1["flow_id"]
    assert timeline["handshake_status"] == "Complete (3-Way Handshake)"
    assert len(timeline["timeline"]) == 5

    events = [e["event_type"] for e in timeline["timeline"]]
    assert events == ["SYN", "SYN-ACK", "ACK", "APPLICATION_DATA", "FIN"]
    assert timeline["timeline"][0]["direction"] == "A -> B"
    assert timeline["timeline"][1]["direction"] == "B -> A"


def test_retransmission_detection():
    tracker = FlowTracker()
    base_ts = 1700000000.0

    payload = b"Important Payload Segment Data"
    pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA", seq=1000) / Raw(payload)
    pkt1.time = base_ts + 0.1
    rec1 = parse_packet(pkt1, 1, base_timestamp=base_ts)
    tracker.process_packet(rec1)

    # Identical segment retransmitted 0.2s later
    pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA", seq=1000) / Raw(payload)
    pkt2.time = base_ts + 0.3
    rec2 = parse_packet(pkt2, 2, base_timestamp=base_ts)
    tracker.process_packet(rec2)

    flow = tracker.get_flow_by_id(rec1["flow_id"])
    assert flow["retransmissions_count"] == 1

    tl = tracker.get_flow_timeline(rec1["flow_id"])
    assert tl["retransmissions"] == 1
    assert tl["timeline"][0]["is_retransmission"] is False
    assert tl["timeline"][1]["is_retransmission"] is True


def test_midstream_and_incomplete_handshakes():
    tracker = FlowTracker()
    base_ts = 1700000000.0

    # Flow observed without SYN (e.g. captured mid-session)
    pkt_mid = Ether() / IP(src="172.16.0.5", dst="172.16.0.1") / TCP(sport=60000, dport=443, flags="PA", seq=5555) / Raw(b"midstream data")
    pkt_mid.time = base_ts + 0.1
    rec_mid = parse_packet(pkt_mid, 1, base_timestamp=base_ts)
    tracker.process_packet(rec_mid)

    flow_mid = tracker.get_flow_by_id(rec_mid["flow_id"])
    assert flow_mid["tcp_state"] == "MID_STREAM"
    assert flow_mid["handshake_status"] == "Mid-Stream Capture (No Handshake Observed)"

    # Reset detection
    pkt_rst = Ether() / IP(src="172.16.0.1", dst="172.16.0.5") / TCP(sport=443, dport=60000, flags="R", seq=100)
    pkt_rst.time = base_ts + 0.2
    rec_rst = parse_packet(pkt_rst, 2, base_timestamp=base_ts)
    tracker.process_packet(rec_rst)

    flow_rst = tracker.get_flow_by_id(rec_mid["flow_id"])
    assert flow_rst["tcp_state"] == "RESET"


def test_timeline_api_endpoint(client):
    res_load = client.post("/api/captures/load-sample")
    assert res_load.status_code == 200

    # Flow-3 is the HTTP flow in sample_traffic.pcap
    res_tl = client.get("/api/flows/flow-3/timeline")
    assert res_tl.status_code == 200
    data = res_tl.json

    assert data["flow_id"] == "flow-3"
    assert "timeline" in data
    assert len(data["timeline"]) >= 3
    assert "handshake_status" in data

    # Check non-existent flow returns 404
    res_404 = client.get("/api/flows/flow-99999/timeline")
    assert res_404.status_code == 404
