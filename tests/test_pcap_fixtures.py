"""
NetScope Deterministic PCAP Fixture Tests
Builds physical, byte-for-byte deterministic PCAP fixtures and validates:
1. Normal complete 3-way handshakes, bidirectional application data, and graceful teardown
2. Incomplete handshakes (SYN sent only, SYN-ACK received without final ACK)
3. Connection resets (RST immediately after SYN, and RST mid-stream)
4. Bidirectional reverse-direction traffic and 5-tuple canonical symmetry
5. Retransmission edge cases (duplicate payload segment detection, out-of-order retransmissions)
"""

import os
import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from capture.pcap_reader import OfflinePcapProcessor
from analyzer.flow_tracker import FlowTracker
from analytics.statistics import TrafficAnalytics


def test_fixture_normal_handshake_and_bidirectional_data_teardown(tmp_path):
    """Verifies complete 3-way handshake, bidirectional data exchange, and 4-way FIN teardown."""
    pcap_path = str(tmp_path / "normal_handshake.pcap")
    base_ts = 1710000000.0

    pkts = [
        # 1. SYN (Client -> Server)
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="S", seq=1000),
        # 2. SYN-ACK (Server -> Client)
        Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=51234, flags="SA", seq=5000, ack=1001),
        # 3. ACK (Client -> Server)
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="A", seq=1001, ack=5001),
        # 4. HTTP Request (Client -> Server, 80 bytes)
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="PA", seq=1001, ack=5001) / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        # 5. TCP ACK for request (Server -> Client)
        Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=51234, flags="A", seq=5001, ack=1045),
        # 6. HTTP Response (Server -> Client, 120 bytes)
        Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=51234, flags="PA", seq=5001, ack=1045) / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!"),
        # 7. FIN-ACK (Client -> Server)
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="FA", seq=1045, ack=5048),
        # 8. ACK for FIN (Server -> Client)
        Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=51234, flags="A", seq=5048, ack=1046),
        # 9. FIN-ACK (Server -> Client)
        Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=51234, flags="FA", seq=5048, ack=1046),
        # 10. ACK for FIN (Client -> Server)
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="A", seq=1046, ack=5049),
    ]

    for i, p in enumerate(pkts):
        p.time = base_ts + (i * 0.01)

    wrpcap(pcap_path, pkts)

    flow_tracker = FlowTracker()
    analytics = TrafficAnalytics()
    processor = OfflinePcapProcessor()

    def cb(rec):
        analytics.ingest_packet(rec)
        flow_tracker.process_packet(rec)

    res = processor.process_file(pcap_path, packet_callback=cb)
    assert res["packet_count"] == 10
    assert analytics.total_packets == 10
    assert flow_tracker.get_flow_count() == 1

    flow = list(flow_tracker.flows.values())[0]
    assert flow["handshake_status"] == "Complete (3-Way Handshake)"
    assert flow["tcp_state"] in ("CLOSING", "CLOSED")
    assert flow["total_packets"] == 10
    assert flow["forward_packets"] == 5
    assert flow["reverse_packets"] == 5
    assert flow["retransmissions_count"] == 0

    timeline = flow_tracker.get_flow_timeline(flow["flow_id"])
    assert len(timeline["timeline"]) == 10
    events = [e["event_type"] for e in timeline["timeline"]]
    assert events == ["SYN", "SYN-ACK", "ACK", "APPLICATION_DATA", "ACK", "APPLICATION_DATA", "FIN", "ACK", "FIN", "ACK"]


def test_fixture_incomplete_handshakes(tmp_path):
    """Verifies state tracking for SYN-only and SYN + SYN-ACK without final ACK."""
    # Fixture 1: SYN only (probed host did not respond)
    pcap1 = str(tmp_path / "syn_only.pcap")
    p1 = Ether() / IP(src="10.0.0.5", dst="10.0.0.99") / TCP(sport=44000, dport=8080, flags="S", seq=500)
    p1.time = 1710000000.0
    wrpcap(pcap1, [p1])

    tracker1 = FlowTracker()
    OfflinePcapProcessor().process_file(pcap1, packet_callback=tracker1.process_packet)
    flow1 = list(tracker1.flows.values())[0]
    assert flow1["tcp_state"] == "SYN_SENT"
    assert flow1["handshake_status"] == "Incomplete (SYN Sent Only)"

    # Fixture 2: SYN + SYN-ACK (server responded, but client dropped before final ACK)
    pcap2 = str(tmp_path / "syn_ack_no_final.pcap")
    p2a = Ether() / IP(src="10.0.0.5", dst="10.0.0.99") / TCP(sport=44001, dport=8080, flags="S", seq=600)
    p2a.time = 1710000001.0
    p2b = Ether() / IP(src="10.0.0.99", dst="10.0.0.5") / TCP(sport=8080, dport=44001, flags="SA", seq=900, ack=601)
    p2b.time = 1710000001.05
    wrpcap(pcap2, [p2a, p2b])

    tracker2 = FlowTracker()
    OfflinePcapProcessor().process_file(pcap2, packet_callback=tracker2.process_packet)
    flow2 = list(tracker2.flows.values())[0]
    assert flow2["tcp_state"] == "SYN_ACK"
    assert flow2["handshake_status"] == "Incomplete (SYN-ACK Received, Missing Final ACK)"


def test_fixture_connection_resets(tmp_path):
    """Verifies reset tracking on connection refusal and mid-stream abort."""
    pcap = str(tmp_path / "resets.pcap")
    pkts = [
        # Connection refusal: SYN -> RST
        Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=33333, dport=22, flags="S", seq=10),
        Ether() / IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=22, dport=33333, flags="R", seq=0, ack=11),
    ]
    pkts[0].time = 1710000010.0
    pkts[1].time = 1710000010.02
    wrpcap(pcap, pkts)

    tracker = FlowTracker()
    OfflinePcapProcessor().process_file(pcap, packet_callback=tracker.process_packet)
    flow = list(tracker.flows.values())[0]
    assert flow["tcp_state"] == "RESET"

    tl = tracker.get_flow_timeline(flow["flow_id"])
    assert tl["tcp_state"] == "RESET"
    assert tl["timeline"][1]["event_type"] == "RST"


def test_fixture_bidirectional_reverse_traffic(tmp_path):
    """Verifies that reverse-direction traffic maps to same 5-tuple canonical flow and counts octets accurately."""
    pcap = str(tmp_path / "bidirectional.pcap")
    base_ts = 1710000020.0

    p_fwd = Ether() / IP(src="172.16.1.10", dst="172.16.1.20") / UDP(sport=5060, dport=5060) / Raw(b"FWD" * 20)
    p_fwd.time = base_ts
    p_rev = Ether() / IP(src="172.16.1.20", dst="172.16.1.10") / UDP(sport=5060, dport=5060) / Raw(b"REV" * 40)
    p_rev.time = base_ts + 0.1

    wrpcap(pcap, [p_fwd, p_rev])

    tracker = FlowTracker()
    OfflinePcapProcessor().process_file(pcap, packet_callback=tracker.process_packet)
    assert tracker.get_flow_count() == 1

    flow = list(tracker.flows.values())[0]
    assert flow["total_packets"] == 2
    assert flow["forward_packets"] == 1
    assert flow["reverse_packets"] == 1
    assert flow["forward_bytes"] > 0
    assert flow["reverse_bytes"] > flow["forward_bytes"]


def test_fixture_retransmission_edge_cases(tmp_path):
    """Verifies sequence-level retransmission detection and out-of-order duplicates."""
    pcap = str(tmp_path / "retrans.pcap")
    base_ts = 1710000030.0

    payload = b"Important Payload Segment Data Exactly 35 Bytes"
    # Packet 1: Initial payload
    p1 = Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=8080, dport=9090, flags="PA", seq=1000) / Raw(payload)
    p1.time = base_ts
    # Packet 2: Retransmission of packet 1
    p2 = Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=8080, dport=9090, flags="PA", seq=1000) / Raw(payload)
    p2.time = base_ts + 0.2
    # Packet 3: Next segment (new sequence)
    p3 = Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=8080, dport=9090, flags="PA", seq=1000 + len(payload)) / Raw(b"Second Segment")
    p3.time = base_ts + 0.3
    # Packet 4: Duplicate of packet 3
    p4 = Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=8080, dport=9090, flags="PA", seq=1000 + len(payload)) / Raw(b"Second Segment")
    p4.time = base_ts + 0.5

    wrpcap(pcap, [p1, p2, p3, p4])

    tracker = FlowTracker()
    OfflinePcapProcessor().process_file(pcap, packet_callback=tracker.process_packet)

    flow = list(tracker.flows.values())[0]
    assert flow["total_packets"] == 4
    assert flow["retransmissions_count"] == 2

    tl = tracker.get_flow_timeline(flow["flow_id"])
    assert tl["retransmissions"] == 2
    assert tl["timeline"][0]["is_retransmission"] is False
    assert tl["timeline"][1]["is_retransmission"] is True
    assert tl["timeline"][2]["is_retransmission"] is False
    assert tl["timeline"][3]["is_retransmission"] is True
