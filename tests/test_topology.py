"""
NetScope X Network Topology Unit Tests
Verifies node and edge generation, internal/external IP categorization,
flow aggregation, and search/protocol filters.
"""

from analytics.topology import build_network_topology, is_private_ip, get_endpoint_role


def test_ip_classification():
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("10.0.5.1") is True
    assert is_private_ip("172.16.0.25") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("255.255.255.255") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("104.16.132.229") is False

    assert "Internal" in get_endpoint_role("192.168.1.50")
    assert "External" in get_endpoint_role("93.184.216.34")
    assert get_endpoint_role("255.255.255.255") == "Broadcast"


def test_build_network_topology_from_flows():
    sample_flows = [
        {
            "flow_id": "flow-1",
            "source_ip": "192.168.1.10",
            "destination_ip": "93.184.216.34",
            "source_port": 50000,
            "destination_port": 80,
            "transport_protocol": "TCP",
            "packet_count": 25,
            "byte_count": 15000,
            "forward_packets": 15,
            "reverse_packets": 10,
            "forward_bytes": 5000,
            "reverse_bytes": 10000,
            "tcp_state": "ESTABLISHED",
        },
        {
            "flow_id": "flow-2",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "source_port": 53000,
            "destination_port": 53,
            "transport_protocol": "UDP",
            "packet_count": 4,
            "byte_count": 400,
            "forward_packets": 2,
            "reverse_packets": 2,
            "forward_bytes": 150,
            "reverse_bytes": 250,
            "tcp_state": "",
        },
    ]

    sample_alerts = [
        {
            "host": "192.168.1.10",
            "target": "93.184.216.34",
            "alert_type": "Observation: Rate Spike",
        }
    ]

    topo = build_network_topology(sample_flows, alerts=sample_alerts)
    assert "nodes" in topo
    assert "edges" in topo
    assert "summary" in topo

    nodes = {n["id"]: n for n in topo["nodes"]}
    assert "192.168.1.10" in nodes
    assert "93.184.216.34" in nodes
    assert "8.8.8.8" in nodes

    # Verify attributes
    node_client = nodes["192.168.1.10"]
    assert node_client["is_internal"] is True
    assert node_client["packet_count"] == 29
    assert "TCP" in node_client["protocols"]
    assert "UDP" in node_client["protocols"]
    assert node_client["alerts_count"] == 1

    node_ext = nodes["93.184.216.34"]
    assert node_ext["is_internal"] is False
    assert node_ext["alerts_count"] == 1

    # Edges
    assert len(topo["edges"]) == 2
    edge_map = {e["id"]: e for e in topo["edges"]}
    edge_key = "edge-192.168.1.10-93.184.216.34"
    assert edge_key in edge_map
    assert edge_map[edge_key]["packet_count"] == 25
    assert "TCP" in edge_map[edge_key]["protocols"]


def test_topology_filtering_and_empty_state():
    # Empty
    empty_topo = build_network_topology([])
    assert len(empty_topo["nodes"]) == 0
    assert len(empty_topo["edges"]) == 0
    assert empty_topo["summary"]["total_nodes"] == 0

    # Min packets filter
    flows = [
        {
            "flow_id": "f1",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "packet_count": 50,
            "byte_count": 5000,
            "transport_protocol": "TCP",
        },
        {
            "flow_id": "f2",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.3",
            "packet_count": 2,
            "byte_count": 200,
            "transport_protocol": "UDP",
        },
    ]

    filtered_topo = build_network_topology(flows, min_packets=10)
    assert len(filtered_topo["nodes"]) == 2
    assert "10.0.0.3" not in {n["id"] for n in filtered_topo["nodes"]}

    # Search filter
    search_topo = build_network_topology(flows, search="10.0.0.2")
    assert len(search_topo["nodes"]) == 1
    assert search_topo["nodes"][0]["id"] == "10.0.0.2"
