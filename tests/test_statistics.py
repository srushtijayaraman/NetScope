"""
NetScope Statistics Unit Tests
Validates deterministic calculations:
- Packet & byte totals
- Protocol distribution percentages (mutually exclusive)
- Average packet size (including zero division protection)
- Capture duration, processing rates (PPS), and throughput (bps/kbps/mbps)
- Top talkers, port aggregation, and timeline bucketing
"""

import pytest
from analytics.statistics import TrafficAnalytics


def test_empty_analytics():
    stats = TrafficAnalytics()
    summary = stats.get_summary()

    assert summary["total_packets"] == 0
    assert summary["total_bytes"] == 0
    assert summary["average_packet_size_bytes"] == 0.0
    assert summary["capture_duration_seconds"] == 0.0
    assert summary["capture_pps"] == 0.0
    assert summary["throughput_bps"] == 0.0
    assert summary["unique_hosts"] == 0


def test_packet_and_byte_counts():
    stats = TrafficAnalytics()
    
    pkt1 = {
        "packet_length": 100,
        "timestamp": 10.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "source_port": 1000,
        "destination_port": 80,
        "tcp_flags": ["SYN"],
        "parsing_status": "Parsed",
    }
    pkt2 = {
        "packet_length": 300,
        "timestamp": 12.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "source_ip": "2.2.2.2",
        "destination_ip": "1.1.1.1",
        "source_port": 80,
        "destination_port": 1000,
        "tcp_flags": ["SYN", "ACK"],
        "parsing_status": "Parsed",
    }
    
    stats.ingest_packet(pkt1)
    stats.ingest_packet(pkt2)

    assert stats.total_packets == 2
    assert stats.total_bytes == 400
    assert stats.get_average_packet_size() == 200.0
    # Duration: 12.0 - 10.0 = 2.0s
    assert stats.get_capture_duration() == 2.0
    # PPS: 2 pkts / 2.0s = 1.0 pps
    assert stats.get_capture_pps() == 1.0
    
    # Throughput: (400 bytes * 8 bits) / 2.0s = 1600 bps = 1.6 kbps
    throughput = stats.get_throughput()
    assert throughput["bps"] == 1600.0
    assert throughput["kbps"] == 1.6


def test_protocol_distribution_percentages():
    stats = TrafficAnalytics()
    
    for _ in range(7):
        stats.ingest_packet({
            "packet_length": 50,
            "timestamp": 10.0,
            "network_protocol": "IPv4",
            "transport_protocol": "TCP",
            "application_protocol": "HTTP",
        })
    for _ in range(3):
        stats.ingest_packet({
            "packet_length": 50,
            "timestamp": 10.0,
            "network_protocol": "IPv4",
            "transport_protocol": "UDP",
            "application_protocol": "DNS",
        })

    dist = stats.get_protocol_distribution()
    assert dist["transport"]["TCP"]["count"] == 7
    assert dist["transport"]["TCP"]["percentage"] == 70.0
    assert dist["transport"]["UDP"]["count"] == 3
    assert dist["transport"]["UDP"]["percentage"] == 30.0
    
    # Percentages within transport layer sum to 100%
    total_pct = sum(v["percentage"] for v in dist["transport"].values())
    assert abs(total_pct - 100.0) < 0.01


def test_top_talkers_and_ports():
    stats = TrafficAnalytics()
    
    # 5 packets from A -> B (500 bytes)
    for _ in range(5):
        stats.ingest_packet({
            "packet_length": 100,
            "timestamp": 1.0,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "destination_port": 443,
        })
    # 2 packets from C -> B (1000 bytes)
    for _ in range(2):
        stats.ingest_packet({
            "packet_length": 500,
            "timestamp": 2.0,
            "source_ip": "10.0.0.3",
            "destination_ip": "10.0.0.2",
            "destination_port": 80,
        })

    # Sort by bytes
    talkers_bytes = stats.get_top_talkers(limit=5, sort_by="bytes")
    # Top source by bytes should be 10.0.0.3 (1000 bytes)
    assert talkers_bytes["sources"][0]["ip"] == "10.0.0.3"
    assert talkers_bytes["sources"][0]["bytes"] == 1000

    # Sort by packets
    talkers_pkts = stats.get_top_talkers(limit=5, sort_by="packets")
    assert talkers_pkts["sources"][0]["ip"] == "10.0.0.1"
    assert talkers_pkts["sources"][0]["packets"] == 5

    # Top ports: 443 has 5 packets, 80 has 2 packets
    ports = stats.get_top_ports(limit=5)
    assert ports[0]["port"] == 443
    assert ports[0]["packets"] == 5
    assert ports[1]["port"] == 80
    assert ports[1]["packets"] == 2


def test_timeline_bucketing():
    stats = TrafficAnalytics()
    # 2 packets in second 100, 1 packet in second 102
    stats.ingest_packet({"packet_length": 60, "timestamp": 100.1})
    stats.ingest_packet({"packet_length": 40, "timestamp": 100.9})
    stats.ingest_packet({"packet_length": 200, "timestamp": 102.5})

    timeline = stats.get_traffic_timeline(max_points=50)
    assert len(timeline) >= 2
    
    first_bucket = timeline[0]
    assert first_bucket["packets"] == 2
    assert first_bucket["bytes"] == 100
