"""
NetScope Filter and Query Tests
Validates filtering, searching, sorting, pagination, and CSV export logic.
"""

import pytest


def test_packet_filtering_workflow(client, sample_pcap_path):
    # Load sample PCAP via API
    res = client.post("/api/captures/load-sample")
    assert res.status_code == 200
    assert res.json["success"] is True

    # 1. Total packets without filters
    res_all = client.get("/api/packets?limit=100")
    assert res_all.status_code == 200
    assert res_all.json["total"] == 60

    # 2. Protocol filter: ARP
    res_arp = client.get("/api/packets?protocol=ARP")
    assert res_arp.status_code == 200
    assert res_arp.json["total"] == 2
    for p in res_arp.json["packets"]:
        assert p["network_protocol"] == "ARP"

    # 3. Protocol filter: DNS
    res_dns = client.get("/api/packets?protocol=DNS")
    assert res_dns.status_code == 200
    assert res_dns.json["total"] >= 2
    for p in res_dns.json["packets"]:
        assert p["application_protocol"] == "DNS"

    # 4. Source IP filter
    res_src = client.get("/api/packets?src_ip=10.0.0.99")
    assert res_src.status_code == 200
    assert res_src.json["total"] == 25  # SYN flood attacker
    for p in res_src.json["packets"]:
        assert p["source_ip"] == "10.0.0.99"

    # 5. Search keyword filter
    res_search = client.get("/api/packets?search=who-has")
    assert res_search.status_code == 200
    assert res_search.json["total"] == 1

    # 6. Pagination test
    res_p1 = client.get("/api/packets?page=1&limit=10")
    assert res_p1.status_code == 200
    assert len(res_p1.json["packets"]) == 10
    assert res_p1.json["page"] == 1
    assert res_p1.json["pages"] == 6

    res_p2 = client.get("/api/packets?page=2&limit=10")
    assert res_p2.status_code == 200
    assert len(res_p2.json["packets"]) == 10
    assert res_p2.json["page"] == 2
    # Ensure disjoint IDs across pages
    ids_p1 = [p["packet_id"] for p in res_p1.json["packets"]]
    ids_p2 = [p["packet_id"] for p in res_p2.json["packets"]]
    assert set(ids_p1).isdisjoint(set(ids_p2))


def test_csv_export_with_filters(client):
    client.post("/api/captures/load-sample")
    
    # Export only ARP packets
    res = client.get("/api/export/csv?protocol=ARP")
    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("text/csv")
    
    lines = res.data.decode("utf-8").strip().split("\r\n")
    # Header + 2 ARP packets
    assert len(lines) == 3
    assert "Packet ID" in lines[0]
    assert "Flow ID" in lines[0]
    assert "Timestamp (ISO)" in lines[0]
    assert "ARP" in lines[1]
    assert "ARP" in lines[2]


def test_filters_by_ports_packet_id_and_flow(client):
    client.post("/api/captures/load-sample")

    # Filter by specific packet_id
    res_pkt = client.get("/api/packets?packet_id=5")
    assert res_pkt.status_code == 200
    assert res_pkt.json["total"] == 1
    assert res_pkt.json["packets"][0]["packet_id"] == 5

    # Filter by dst_port 80
    res_port = client.get("/api/packets?dst_port=80")
    assert res_port.status_code == 200
    assert res_port.json["total"] > 0
    for p in res_port.json["packets"]:
        assert p["destination_port"] == 80

    # Test Flow API and flow_id filtering
    res_flows = client.get("/api/flows")
    assert res_flows.status_code == 200
    flows = res_flows.json["flows"]
    assert len(flows) > 0
    sample_flow = flows[0]
    flow_id = sample_flow["flow_id"]

    # Retrieve flow details
    res_fdetail = client.get(f"/api/flows/{flow_id}")
    assert res_fdetail.status_code == 200
    assert res_fdetail.json["flow_id"] == flow_id
    assert "packet_ids" in res_fdetail.json

    # Filter packets by flow_id
    res_fpkts = client.get(f"/api/packets?flow_id={flow_id}")
    assert res_fpkts.status_code == 200
    assert res_fpkts.json["total"] == sample_flow["packet_count"]
    for p in res_fpkts.json["packets"]:
        assert p["flow_id"] == flow_id

    # 404 for unknown flow
    res_f404 = client.get("/api/flows/nonexistent-flow-id")
    assert res_f404.status_code == 404

