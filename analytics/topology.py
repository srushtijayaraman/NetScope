"""
NetScope X Network Topology Subsystem
Analyzes flow tracking state and packet streams to construct an interactive,
graph-based host communication topology. Identifies internal/external addressing boundaries,
aggregates connection intensity, and provides endpoint risk scoring.
"""

import ipaddress
from collections import defaultdict


def is_private_ip(ip_str: str) -> bool:
    """Accurately classifies whether an IP address is private/internal or external."""
    if not ip_str or ip_str in ("Broadcast", "0.0.0.0", "255.255.255.255"):
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        # Non-standard or hostname string
        return False


def get_endpoint_role(ip_str: str) -> str:
    """Infers high-level endpoint role from IP address semantics."""
    if not ip_str:
        return "Unknown"
    if ip_str == "255.255.255.255":
        return "Broadcast"
    if ip_str.startswith("224.") or ip_str.startswith("ff"):
        return "Multicast Group"
    if ip_str.startswith("127.") or ip_str == "::1":
        return "Loopback"
    if is_private_ip(ip_str):
        if ip_str.endswith(".1") or ip_str.endswith(".254"):
            return "Internal Gateway / Router"
        return "Internal Endpoint"
    return "External Endpoint"


def build_network_topology(flows: list[dict], alerts: list[dict] = None, min_packets: int = 1, protocol_filter: str = None, search: str = None) -> dict:
    """
    Constructs an interactive graph topology (nodes and edges) from 5-tuple flow records.
    Filters by minimum packet volume, protocol, or host query.
    """
    alerts = alerts or []
    
    # Map alerts to hosts
    host_alerts = defaultdict(list)
    for alt in alerts:
        h = alt.get("host")
        if h:
            host_alerts[h].append(alt.get("alert_type") or alt.get("rule_name") or "Alert")
        tgt = alt.get("target")
        if tgt and tgt != "Unknown" and not tgt.startswith("Distinct"):
            host_alerts[tgt].append(alt.get("alert_type") or alt.get("rule_name") or "Alert")

    node_stats = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "sent_packets": 0,
        "recv_packets": 0,
        "sent_bytes": 0,
        "recv_bytes": 0,
        "protocols": set(),
        "flows": set(),
        "peers": set(),
    })

    edge_stats = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "protocols": set(),
        "flows": [],
        "forward_packets": 0,
        "reverse_packets": 0,
        "tcp_states": set(),
    })

    for f in flows:
        sip = f.get("source_ip")
        dip = f.get("destination_ip")
        if not sip and f.get("endpoint_a"):
            ea = str(f["endpoint_a"])
            sip = ea.rsplit(":", 1)[0] if ":" in ea else ea
        if not dip and f.get("endpoint_b"):
            eb = str(f["endpoint_b"])
            dip = eb.rsplit(":", 1)[0] if ":" in eb else eb

        if not sip or not dip or sip == dip:
            continue

        proto = f.get("transport_protocol") or f.get("protocol") or "IP"
        if protocol_filter and protocol_filter.upper() not in (proto.upper(), (f.get("application_protocol") or "").upper()):
            continue

        pkts = f.get("packet_count") or f.get("total_packets") or 0
        bytes_ = f.get("byte_count") or f.get("total_bytes") or 0
        f_pkts = f.get("forward_packets", pkts)
        r_pkts = f.get("reverse_packets", 0)
        f_bytes = f.get("forward_bytes", bytes_)
        r_bytes = f.get("reverse_bytes", 0)
        fid = f.get("flow_id", "")
        tcp_state = f.get("tcp_state", "")

        # Node A
        node_stats[sip]["packet_count"] += pkts
        node_stats[sip]["byte_count"] += bytes_
        node_stats[sip]["sent_packets"] += f_pkts
        node_stats[sip]["recv_packets"] += r_pkts
        node_stats[sip]["sent_bytes"] += f_bytes
        node_stats[sip]["recv_bytes"] += r_bytes
        node_stats[sip]["protocols"].add(proto)
        if fid:
            node_stats[sip]["flows"].add(fid)
        node_stats[sip]["peers"].add(dip)

        # Node B
        node_stats[dip]["packet_count"] += pkts
        node_stats[dip]["byte_count"] += bytes_
        node_stats[dip]["sent_packets"] += r_pkts
        node_stats[dip]["recv_packets"] += f_pkts
        node_stats[dip]["sent_bytes"] += r_bytes
        node_stats[dip]["recv_bytes"] += f_bytes
        node_stats[dip]["protocols"].add(proto)
        if fid:
            node_stats[dip]["flows"].add(fid)
        node_stats[dip]["peers"].add(sip)

        # Canonical Edge key (sorted to ensure undirected peer link)
        edge_key = tuple(sorted([sip, dip]))
        edge_stats[edge_key]["packet_count"] += pkts
        edge_stats[edge_key]["byte_count"] += bytes_
        edge_stats[edge_key]["protocols"].add(proto)
        if fid:
            edge_stats[edge_key]["flows"].append({
                "flow_id": fid,
                "protocol": proto,
                "source_port": f.get("source_port"),
                "destination_port": f.get("destination_port"),
                "packets": pkts,
                "bytes": bytes_,
                "tcp_state": tcp_state,
            })
        if sip == edge_key[0]:
            edge_stats[edge_key]["forward_packets"] += f_pkts
            edge_stats[edge_key]["reverse_packets"] += r_pkts
        else:
            edge_stats[edge_key]["forward_packets"] += r_pkts
            edge_stats[edge_key]["reverse_packets"] += f_pkts
        if tcp_state:
            edge_stats[edge_key]["tcp_states"].add(tcp_state)

    # Search filter
    search_q = (search or "").strip().lower()

    # Build Nodes
    nodes = []
    max_node_pkts = max((d["packet_count"] for d in node_stats.values()), default=1) or 1
    for ip, d in node_stats.items():
        if d["packet_count"] < min_packets:
            continue
        if search_q and search_q not in ip.lower():
            continue

        is_priv = is_private_ip(ip)
        alerts_list = host_alerts.get(ip, [])
        risk_level = "High" if len(alerts_list) >= 2 else ("Medium" if len(alerts_list) == 1 else "Normal")

        nodes.append({
            "id": ip,
            "label": ip,
            "ip": ip,
            "is_internal": is_priv,
            "role": get_endpoint_role(ip),
            "packet_count": d["packet_count"],
            "byte_count": d["byte_count"],
            "sent_packets": d["sent_packets"],
            "recv_packets": d["recv_packets"],
            "sent_bytes": d["sent_bytes"],
            "recv_bytes": d["recv_bytes"],
            "protocols": sorted(list(d["protocols"])),
            "flows_count": len(d["flows"]),
            "peer_count": len(d["peers"]),
            "alerts_count": len(alerts_list),
            "alerts": alerts_list[:5],
            "risk_level": risk_level,
            "relative_size": round(0.4 + 0.6 * (d["packet_count"] / max_node_pkts), 2),
        })

    # Sort nodes by packet volume
    nodes.sort(key=lambda x: x["packet_count"], reverse=True)
    valid_node_ids = {n["id"] for n in nodes}

    # Build Edges
    edges = []
    max_edge_pkts = max((d["packet_count"] for d in edge_stats.values()), default=1) or 1
    for (src, dst), d in edge_stats.items():
        if src not in valid_node_ids or dst not in valid_node_ids:
            continue
        if d["packet_count"] < min_packets:
            continue

        protos = sorted(list(d["protocols"]))
        dominant_proto = protos[0] if protos else "IP"
        intensity = round(0.2 + 0.8 * (d["packet_count"] / max_edge_pkts), 2)

        edges.append({
            "id": f"edge-{src}-{dst}",
            "source": src,
            "target": dst,
            "packet_count": d["packet_count"],
            "byte_count": d["byte_count"],
            "protocols": protos,
            "dominant_protocol": dominant_proto,
            "intensity": intensity,
            "flows_count": len(d["flows"]),
            "flows": d["flows"][:10],
            "tcp_states": sorted(list(d["tcp_states"])),
        })

    edges.sort(key=lambda x: x["packet_count"], reverse=True)

    internal_count = sum(1 for n in nodes if n["is_internal"])
    external_count = len(nodes) - internal_count

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "internal_nodes": internal_count,
            "external_nodes": external_count,
            "total_edges": len(edges),
            "dominant_endpoint": nodes[0]["id"] if nodes else "None",
            "active_protocols": sorted(list({p for n in nodes for p in n["protocols"]})),
        }
    }
