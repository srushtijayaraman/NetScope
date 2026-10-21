"""
NetScope Flow Tracker
Aggregates bidirectional network flows based on canonical 5-tuples.
Maintains stateful statistics: flow duration, packet counts, byte volumes, and TCP lifecycle.
"""

from collections import defaultdict


class FlowTracker:
    def __init__(self):
        # Maps canonical flow key -> flow metadata dict
        self.flows = {}

    def _canonical_key(self, src_ip: str, dst_ip: str, proto: str, sport: int, dport: int):
        """Builds a symmetric canonical key so packets in both directions map to the same flow."""
        endpoint1 = (src_ip or "", sport or 0)
        endpoint2 = (dst_ip or "", dport or 0)
        if endpoint1 <= endpoint2:
            return (endpoint1[0], endpoint2[0], proto, endpoint1[1], endpoint2[1])
        else:
            return (endpoint2[0], endpoint1[0], proto, endpoint2[1], endpoint1[1])

    def process_packet(self, record: dict):
        """Updates flow state with an incoming normalized packet record."""
        src_ip = record.get("source_ip")
        dst_ip = record.get("destination_ip")
        proto = record.get("transport_protocol") or "OTHER"
        sport = record.get("source_port")
        dport = record.get("destination_port")
        pkt_len = record.get("packet_length", 0)
        ts = record.get("timestamp", 0.0)
        app_proto = record.get("application_protocol")

        if not src_ip or not dst_ip:
            return

        key = self._canonical_key(src_ip, dst_ip, proto, sport, dport)
        is_forward = (src_ip == key[0] and (sport or 0) == key[3])

        if key not in self.flows:
            self.flows[key] = {
                "flow_id": f"flow-{len(self.flows) + 1}",
                "endpoint_a": f"{key[0]}:{key[3]}",
                "endpoint_b": f"{key[1]}:{key[4]}",
                "transport_protocol": proto,
                "application_protocol": app_proto if app_proto != "Unknown" else "Unclassified",
                "start_time": ts,
                "end_time": ts,
                "duration": 0.0,
                "forward_packets": 0,
                "forward_bytes": 0,
                "reverse_packets": 0,
                "reverse_bytes": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "tcp_state": "INIT" if proto == "TCP" else "STATELESS",
            }

        flow = self.flows[key]
        flow["end_time"] = max(flow["end_time"], ts)
        flow["duration"] = round(flow["end_time"] - flow["start_time"], 3)
        flow["total_packets"] += 1
        flow["total_bytes"] += pkt_len

        if app_proto and app_proto != "Unknown" and flow["application_protocol"] == "Unclassified":
            flow["application_protocol"] = app_proto

        if is_forward:
            flow["forward_packets"] += 1
            flow["forward_bytes"] += pkt_len
        else:
            flow["reverse_packets"] += 1
            flow["reverse_bytes"] += pkt_len

        # TCP State tracking
        if proto == "TCP":
            flags = record.get("tcp_flags", [])
            if "RST" in flags:
                flow["tcp_state"] = "RESET"
            elif "FIN" in flags:
                flow["tcp_state"] = "CLOSING" if flow["tcp_state"] == "ESTABLISHED" else "CLOSED"
            elif "SYN" in flags and "ACK" in flags:
                flow["tcp_state"] = "SYN_ACK"
            elif "SYN" in flags:
                flow["tcp_state"] = "SYN_SENT"
            elif "ACK" in flags and flow["tcp_state"] in ("SYN_ACK", "SYN_SENT"):
                flow["tcp_state"] = "ESTABLISHED"

    def get_flow_count(self) -> int:
        return len(self.flows)

    def get_top_flows(self, limit: int = 10, sort_by: str = "bytes") -> list[dict]:
        """Returns sorted flow summaries."""
        sort_key = "total_bytes" if sort_by == "bytes" else "total_packets"
        sorted_flows = sorted(self.flows.values(), key=lambda f: f[sort_key], reverse=True)
        return sorted_flows[:limit]

    def reset(self):
        self.flows.clear()
