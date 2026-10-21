"""
NetScope Flow Tracker
Aggregates bidirectional network flows based on canonical 5-tuples.
Maintains stateful statistics: flow duration, packet counts, byte volumes, and TCP lifecycle.
Associates individual packet records with their parent flow identifiers for cross-drilldown.
"""

from collections import defaultdict


class FlowTracker:
    def __init__(self):
        # Maps canonical flow key -> flow metadata dict
        self.flows = {}
        # Maps flow_id -> flow metadata dict for O(1) direct lookup
        self.flows_by_id = {}
        # Maps canonical flow key -> set of observed (is_forward, seq, length) tuples
        self.flow_segments = defaultdict(set)

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
        pkt_id = record.get("packet_id")

        if not src_ip or not dst_ip:
            return

        key = self._canonical_key(src_ip, dst_ip, proto, sport, dport)
        is_forward = (src_ip == key[0] and (sport or 0) == key[3])

        if key not in self.flows:
            flow_num = len(self.flows) + 1
            flow_obj = {
                "flow_id": f"flow-{flow_num}",
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
                "handshake_status": "Pending" if proto == "TCP" else "Not Applicable",
                "retransmissions_count": 0,
                "packet_ids": [],
                "timeline": [],
                "_saw_syn": False,
                "_saw_syn_ack": False,
                "_saw_handshake_ack": False,
                "_saw_fin": False,
                "_saw_rst": False,
            }
            self.flows[key] = flow_obj
            self.flows_by_id[flow_obj["flow_id"]] = flow_obj

        flow = self.flows[key]
        record["flow_id"] = flow["flow_id"]
        if pkt_id is not None:
            flow["packet_ids"].append(pkt_id)

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

        # TCP analysis: flags, states, retransmissions, timeline events
        flags = record.get("tcp_flags", [])
        is_retrans = False
        event_type = "DATA"

        if proto == "TCP":
            seq = record.get("tcp_seq")
            ack = record.get("tcp_ack")

            # Event classification
            if "RST" in flags:
                event_type = "RST"
                flow["_saw_rst"] = True
            elif "FIN" in flags:
                event_type = "FIN"
                flow["_saw_fin"] = True
            elif "SYN" in flags and "ACK" in flags:
                event_type = "SYN-ACK"
                flow["_saw_syn_ack"] = True
            elif "SYN" in flags:
                event_type = "SYN"
                flow["_saw_syn"] = True
            elif "PSH" in flags or (pkt_len > 54 and "ACK" in flags):
                event_type = "APPLICATION_DATA"
                if flow["_saw_syn_ack"] and not flow["_saw_handshake_ack"] and is_forward:
                    flow["_saw_handshake_ack"] = True
            elif flags == ["ACK"]:
                event_type = "ACK"
                if flow["_saw_syn_ack"] and not flow["_saw_handshake_ack"] and is_forward:
                    flow["_saw_handshake_ack"] = True
            else:
                event_type = ",".join(flags) if flags else "TCP_SEGMENT"

            # Retransmission check (only for segments with payload or SYN/FIN)
            if seq is not None and ("SYN" in flags or "FIN" in flags or pkt_len > 54):
                seg_key = (is_forward, seq, pkt_len)
                if seg_key in self.flow_segments[key]:
                    is_retrans = True
                    flow["retransmissions_count"] += 1
                else:
                    self.flow_segments[key].add(seg_key)

            # Update TCP state and handshake status
            if flow["_saw_rst"]:
                flow["tcp_state"] = "RESET"
            elif flow["_saw_fin"]:
                flow["tcp_state"] = "CLOSING" if flow["_saw_handshake_ack"] or flow["tcp_state"] == "ESTABLISHED" else "CLOSED"
            elif flow["_saw_syn"] and flow["_saw_syn_ack"] and flow["_saw_handshake_ack"]:
                flow["tcp_state"] = "ESTABLISHED"
            elif flow["_saw_syn_ack"]:
                flow["tcp_state"] = "SYN_ACK"
            elif flow["_saw_syn"]:
                flow["tcp_state"] = "SYN_SENT"
            elif not flow["_saw_syn"] and not flow["_saw_syn_ack"]:
                flow["tcp_state"] = "MID_STREAM"
            else:
                flow["tcp_state"] = "ESTABLISHED"

            # Handshake categorization
            if flow["_saw_syn"] and flow["_saw_syn_ack"] and flow["_saw_handshake_ack"]:
                flow["handshake_status"] = "Complete (3-Way Handshake)"
            elif flow["_saw_syn"] and flow["_saw_syn_ack"] and not flow["_saw_handshake_ack"]:
                flow["handshake_status"] = "Incomplete (SYN-ACK Received, Missing Final ACK)"
            elif flow["_saw_syn"] and not flow["_saw_syn_ack"]:
                flow["handshake_status"] = "Incomplete (SYN Sent Only)"
            elif flow["_saw_syn_ack"] and not flow["_saw_syn"]:
                flow["handshake_status"] = "Incomplete (SYN-ACK without initial SYN)"
            elif not flow["_saw_syn"] and not flow["_saw_syn_ack"]:
                flow["handshake_status"] = "Mid-Stream Capture (No Handshake Observed)"
        else:
            event_type = proto
            flow["handshake_status"] = "Not Applicable (Stateless Protocol)"

        # Append timeline event (bounded to 500 events per flow)
        if len(flow["timeline"]) < 500:
            flow["timeline"].append({
                "packet_id": pkt_id,
                "timestamp": ts,
                "relative_time_sec": round(ts - flow["start_time"], 4),
                "direction": "A -> B" if is_forward else "B -> A",
                "source": f"{src_ip}:{sport}" if sport else src_ip,
                "destination": f"{dst_ip}:{dport}" if dport else dst_ip,
                "event_type": event_type,
                "flags": flags,
                "tcp_seq": record.get("tcp_seq"),
                "tcp_ack": record.get("tcp_ack"),
                "packet_length": pkt_len,
                "is_retransmission": is_retrans,
                "summary": record.get("summary", ""),
            })

    def get_flow_count(self) -> int:
        return len(self.flows)

    def get_flow_by_id(self, flow_id: str) -> dict | None:
        flow = self.flows_by_id.get(flow_id)
        if not flow:
            return None
        return {k: v for k, v in flow.items() if not k.startswith("_")}

    def get_top_flows(self, limit: int = 10, sort_by: str = "bytes") -> list[dict]:
        """Returns sorted flow summaries without exposing unbounded packet ID arrays."""
        sort_key = "total_bytes" if sort_by == "bytes" else "total_packets"
        sorted_flows = sorted(self.flows.values(), key=lambda f: f[sort_key], reverse=True)
        results = []
        for f in sorted_flows[:limit]:
            results.append({
                "flow_id": f["flow_id"],
                "endpoint_a": f["endpoint_a"],
                "endpoint_b": f["endpoint_b"],
                "transport_protocol": f["transport_protocol"],
                "application_protocol": f["application_protocol"],
                "start_time": f["start_time"],
                "end_time": f["end_time"],
                "duration": f["duration"],
                "forward_packets": f["forward_packets"],
                "forward_bytes": f["forward_bytes"],
                "reverse_packets": f["reverse_packets"],
                "reverse_bytes": f["reverse_bytes"],
                "total_packets": f["total_packets"],
                "total_bytes": f["total_bytes"],
                "tcp_state": f["tcp_state"],
                "handshake_status": f.get("handshake_status", "Not Applicable"),
                "retransmissions": f.get("retransmissions_count", 0),
                "packet_count": len(f["packet_ids"]),
            })
        return results

    def get_flow_timeline(self, flow_id: str) -> dict | None:
        """Returns chronological TCP/transport conversation timeline events for a flow."""
        flow = self.flows_by_id.get(flow_id)
        if not flow:
            return None

        return {
            "flow_id": flow["flow_id"],
            "endpoint_a": flow["endpoint_a"],
            "endpoint_b": flow["endpoint_b"],
            "transport_protocol": flow["transport_protocol"],
            "application_protocol": flow["application_protocol"],
            "tcp_state": flow["tcp_state"],
            "handshake_status": flow.get("handshake_status", "Not Applicable"),
            "retransmissions": flow.get("retransmissions_count", 0),
            "start_time": flow["start_time"],
            "end_time": flow["end_time"],
            "duration": flow["duration"],
            "forward_packets": flow["forward_packets"],
            "reverse_packets": flow["reverse_packets"],
            "total_packets": flow["total_packets"],
            "total_bytes": flow["total_bytes"],
            "events_count": len(flow.get("timeline", [])),
            "timeline": flow.get("timeline", []),
        }

    def reset(self):
        self.flows.clear()
        self.flows_by_id.clear()
        self.flow_segments.clear()
