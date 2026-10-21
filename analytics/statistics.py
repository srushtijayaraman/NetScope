"""
NetScope Analytics Engine
Computes deterministic, academically rigorous network statistics:
- Total packets and byte counts
- Protocol distributions (Transport, Network, Application)
- Capture duration, processing rates (PPS), and throughput (bps/kbps/Mbps)
- Top talkers (Source, Destination, Host)
- Port aggregation and TCP flag breakdowns
- Time-series bucketing for traffic timeline charts
"""

import math
from collections import defaultdict, Counter


class TrafficAnalytics:
    def __init__(self):
        self.reset()

    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.min_timestamp = None
        self.max_timestamp = None
        
        # Processing duration metadata
        self.processing_time_sec = 0.0
        
        # Protocol counts
        self.transport_counts = Counter()
        self.network_counts = Counter()
        self.application_counts = Counter()
        
        # Host / IP metrics
        self.src_ip_packets = Counter()
        self.src_ip_bytes = Counter()
        self.dst_ip_packets = Counter()
        self.dst_ip_bytes = Counter()
        
        # Port metrics
        self.dst_port_packets = Counter()
        self.src_port_packets = Counter()
        
        # TCP Flags
        self.tcp_flags_counts = Counter()
        
        # Error & status tracking
        self.status_counts = Counter()
        self.queue_drops = 0
        
        # Time-series buckets (key: epoch second as int -> {packets, bytes})
        self.timeline_buckets = defaultdict(lambda: {"packets": 0, "bytes": 0})

    def ingest_packet(self, record: dict):
        """Updates all internal counters with a single parsed packet record."""
        self.total_packets += 1
        pkt_len = record.get("packet_length", 0)
        self.total_bytes += pkt_len
        
        ts = record.get("timestamp")
        if ts is not None and ts > 0:
            if self.min_timestamp is None or ts < self.min_timestamp:
                self.min_timestamp = ts
            if self.max_timestamp is None or ts > self.max_timestamp:
                self.max_timestamp = ts
            
            # 1-second bucketing
            sec_bucket = int(ts)
            self.timeline_buckets[sec_bucket]["packets"] += 1
            self.timeline_buckets[sec_bucket]["bytes"] += pkt_len

        # Network protocol
        net_proto = record.get("network_protocol") or "Unknown"
        self.network_counts[net_proto] += 1
        
        # Transport protocol
        trans_proto = record.get("transport_protocol") or "None"
        self.transport_counts[trans_proto] += 1
        
        # Application protocol
        app_proto = record.get("application_protocol") or "Unknown"
        self.application_counts[app_proto] += 1
        
        # IP aggregations
        src_ip = record.get("source_ip")
        dst_ip = record.get("destination_ip")
        if src_ip:
            self.src_ip_packets[src_ip] += 1
            self.src_ip_bytes[src_ip] += pkt_len
        if dst_ip:
            self.dst_ip_packets[dst_ip] += 1
            self.dst_ip_bytes[dst_ip] += pkt_len
            
        # Port aggregations
        dport = record.get("destination_port")
        sport = record.get("source_port")
        if dport is not None:
            self.dst_port_packets[dport] += 1
        if sport is not None:
            self.src_port_packets[sport] += 1
            
        # TCP Flags
        for flag in record.get("tcp_flags", []):
            self.tcp_flags_counts[flag] += 1
            
        # Status
        status = record.get("parsing_status", "Parsed")
        self.status_counts[status] += 1

    def get_capture_duration(self) -> float:
        """Returns the capture span in seconds based on recorded packet timestamps."""
        if self.min_timestamp is None or self.max_timestamp is None:
            return 0.0
        return max(0.0, self.max_timestamp - self.min_timestamp)

    def get_average_packet_size(self) -> float:
        """Average packet size in bytes: total_bytes / total_packets."""
        if self.total_packets == 0:
            return 0.0
        return round(self.total_bytes / self.total_packets, 2)

    def get_capture_pps(self) -> float:
        """Capture rate (Packets Per Second) across the capture timeline."""
        duration = self.get_capture_duration()
        if duration <= 0.0:
            return float(self.total_packets) if self.total_packets > 0 else 0.0
        return round(self.total_packets / duration, 2)

    def get_processing_pps(self) -> float:
        """Processing rate (Packets Per Second) based on actual wall-clock elapsed time."""
        if self.processing_time_sec <= 0.0:
            return 0.0
        return round(self.total_packets / self.processing_time_sec, 2)

    def get_throughput(self) -> dict:
        """
        Throughput calculated as: (total_bytes * 8) / capture_duration.
        Safe against zero duration.
        """
        duration = self.get_capture_duration()
        if duration <= 0.0:
            bps = float(self.total_bytes * 8) if self.total_bytes > 0 else 0.0
        else:
            bps = (self.total_bytes * 8) / duration

        return {
            "bps": round(bps, 2),
            "kbps": round(bps / 1_000.0, 2),
            "mbps": round(bps / 1_000_000.0, 4),
        }

    def get_protocol_distribution(self) -> dict:
        """
        Returns mutually exclusive protocol distributions for Transport and Network layers,
        plus the Application layer breakdown. Handles zero denominators cleanly.
        """
        def calc_shares(counter: Counter):
            total = sum(counter.values())
            res = {}
            for name, count in counter.most_common():
                pct = round((count / total * 100.0), 2) if total > 0 else 0.0
                res[name] = {"count": count, "percentage": pct}
            return res

        return {
            "transport": calc_shares(self.transport_counts),
            "network": calc_shares(self.network_counts),
            "application": calc_shares(self.application_counts),
        }

    def get_top_talkers(self, limit: int = 10, sort_by: str = "bytes") -> dict:
        """
        Aggregates traffic by Source IP, Destination IP, and Unified Host IP.
        """
        def rank(packets_counter, bytes_counter):
            all_ips = set(packets_counter.keys()) | set(bytes_counter.keys())
            items = []
            for ip in all_ips:
                items.append({
                    "ip": ip,
                    "packets": packets_counter[ip],
                    "bytes": bytes_counter[ip],
                })
            key = "bytes" if sort_by == "bytes" else "packets"
            items.sort(key=lambda x: x[key], reverse=True)
            return items[:limit]

        # Unified hosts
        host_packets = Counter()
        host_bytes = Counter()
        for ip, count in self.src_ip_packets.items():
            host_packets[ip] += count
            host_bytes[ip] += self.src_ip_bytes[ip]
        for ip, count in self.dst_ip_packets.items():
            host_packets[ip] += count
            host_bytes[ip] += self.dst_ip_bytes[ip]

        return {
            "sources": rank(self.src_ip_packets, self.src_ip_bytes),
            "destinations": rank(self.dst_ip_packets, self.dst_ip_bytes),
            "hosts": rank(host_packets, host_bytes),
        }

    def get_top_ports(self, limit: int = 10) -> list[dict]:
        """Returns top destination ports (standard proxy for service/application targets)."""
        total = sum(self.dst_port_packets.values())
        results = []
        for port, count in self.dst_port_packets.most_common(limit):
            pct = round((count / total * 100.0), 2) if total > 0 else 0.0
            results.append({"port": port, "packets": count, "percentage": pct})
        return results

    def get_traffic_timeline(self, max_points: int = 100) -> list[dict]:
        """
        Returns chronological time buckets for timeline graphs.
        If buckets exceed max_points, groups adjacent seconds into larger intervals.
        """
        if not self.timeline_buckets:
            return []

        sorted_secs = sorted(self.timeline_buckets.keys())
        first_sec = sorted_secs[0]
        last_sec = sorted_secs[-1]
        total_span = last_sec - first_sec + 1

        step = max(1, math.ceil(total_span / max_points))

        timeline = []
        curr_sec = first_sec
        while curr_sec <= last_sec:
            next_sec = curr_sec + step
            bucket_pkts = 0
            bucket_bytes = 0
            for s in range(curr_sec, next_sec):
                if s in self.timeline_buckets:
                    bucket_pkts += self.timeline_buckets[s]["packets"]
                    bucket_bytes += self.timeline_buckets[s]["bytes"]

            bps = (bucket_bytes * 8) / step
            pps = bucket_pkts / step
            timeline.append({
                "timestamp": curr_sec,
                "packets": bucket_pkts,
                "bytes": bucket_bytes,
                "pps": round(pps, 2),
                "kbps": round(bps / 1_000.0, 2),
            })
            curr_sec = next_sec

        return timeline

    def get_summary(self) -> dict:
        """Returns a unified high-level summary of all key metrics."""
        unique_ips = len(set(self.src_ip_packets.keys()) | set(self.dst_ip_packets.keys()))
        duration = self.get_capture_duration()
        throughput = self.get_throughput()

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "capture_duration_seconds": round(duration, 3),
            "processing_time_seconds": round(self.processing_time_sec, 4),
            "capture_pps": self.get_capture_pps(),
            "processing_pps": self.get_processing_pps(),
            "average_packet_size_bytes": self.get_average_packet_size(),
            "throughput_bps": throughput["bps"],
            "throughput_kbps": throughput["kbps"],
            "throughput_mbps": throughput["mbps"],
            "unique_hosts": unique_ips,
            "tcp_flags": dict(self.tcp_flags_counts),
            "status_breakdown": dict(self.status_counts),
            "parsing_errors": self.status_counts.get("Malformed", 0),
            "queue_drops": self.queue_drops,
        }
