"""
NetScope Rule-Based Anomaly Detection Module
Evaluates deterministic network traffic heuristics:
1. Volumetric packet rate spikes
2. Throughput byte rate threshold violations
3. SYN flood patterns (high SYN count without completion)
4. Port scans (rapid probes across multiple distinct destination ports)
5. Dominant high-volume traffic sources

All rules are explainable, bounded, configurable, and include cooldowns.
"""

from collections import defaultdict, deque


class AnomalyDetector:
    def __init__(self, config=None):
        self.packet_rate_threshold = getattr(config, "PACKET_RATE_THRESHOLD", 150)
        self.byte_rate_threshold = getattr(config, "BYTE_RATE_THRESHOLD", 500_000)
        self.syn_flood_threshold = getattr(config, "SYN_FLOOD_THRESHOLD", 20)
        self.port_scan_threshold = getattr(config, "PORT_SCAN_THRESHOLD", 15)
        self.host_volume_ratio = getattr(config, "HOST_VOLUME_RATIO_THRESHOLD", 0.5)
        self.cooldown_sec = getattr(config, "ANOMALY_COOLDOWN_SECONDS", 10)

        self.alerts = []
        self._last_alert_time = {}  # (alert_type, target) -> timestamp
        
        # Sliding window state
        # src_ip -> deque of timestamps
        self._syn_history = defaultdict(deque)
        # src_ip -> deque of (timestamp, dport)
        self._port_scan_history = defaultdict(deque)

    def reset(self):
        self.alerts.clear()
        self._last_alert_time.clear()
        self._syn_history.clear()
        self._port_scan_history.clear()

    def _can_fire(self, alert_type: str, target: str, current_ts: float) -> bool:
        """Enforces a cooldown to prevent repetitive alerting."""
        key = (alert_type, target)
        last_time = self._last_alert_time.get(key)
        if last_time is None or (current_ts - last_time) >= self.cooldown_sec:
            self._last_alert_time[key] = current_ts
            return True
        return False

    def evaluate_packet(self, record: dict) -> list[dict]:
        """
        Evaluates a single packet for real-time or streaming stateful anomalies (SYN floods, port scans).
        Returns a list of newly triggered alerts.
        """
        new_alerts = []
        src_ip = record.get("source_ip")
        dst_ip = record.get("destination_ip")
        ts = record.get("timestamp", 0.0)
        proto = record.get("transport_protocol")
        flags = record.get("tcp_flags", [])
        dport = record.get("destination_port")

        if not src_ip or ts <= 0:
            return new_alerts

        # Rule 1: SYN Flood Detection (5-second sliding window)
        if proto == "TCP" and "SYN" in flags and "ACK" not in flags:
            history = self._syn_history[src_ip]
            history.append(ts)
            while history and (ts - history[0]) > 5.0:
                history.popleft()

            if len(history) >= self.syn_flood_threshold:
                if self._can_fire("SYN_FLOOD", src_ip, ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "SYN Flood Warning",
                        "severity": "HIGH",
                        "timestamp": ts,
                        "host": src_ip,
                        "observed_metric": f"{len(history)} SYNs in 5s",
                        "configured_threshold": f"{self.syn_flood_threshold} SYNs in 5s",
                        "explanation": f"Host {src_ip} transmitted {len(history)} standalone TCP SYN packets within 5 seconds without normal handshake progression.",
                        "evidence": {"source_ip": src_ip, "syn_count": len(history), "window_seconds": 5.0},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # Rule 2: Port Scanning Detection (5-second sliding window)
        if proto in ("TCP", "UDP") and dport is not None:
            scan_hist = self._port_scan_history[src_ip]
            scan_hist.append((ts, dport))
            while scan_hist and (ts - scan_hist[0][0]) > 5.0:
                scan_hist.popleft()

            unique_ports = {p for _, p in scan_hist}
            if len(unique_ports) >= self.port_scan_threshold:
                if self._can_fire("PORT_SCAN", src_ip, ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Port Scan Detected",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "host": src_ip,
                        "observed_metric": f"{len(unique_ports)} distinct ports queried in 5s",
                        "configured_threshold": f"{self.port_scan_threshold} ports in 5s",
                        "explanation": f"Host {src_ip} probed {len(unique_ports)} unique destination ports within 5 seconds, characteristic of reconnaissance/scanning.",
                        "evidence": {"source_ip": src_ip, "port_count": len(unique_ports), "window_seconds": 5.0},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        return new_alerts

    def evaluate_batch_statistics(self, analytics_summary: dict, timeline: list[dict], top_talkers: dict) -> list[dict]:
        """
        Evaluates session-wide volumetric anomalies across time-buckets and host distributions.
        """
        new_alerts = []

        # Rule 3: High Packet Rate Spike in any timeline interval
        for bucket in timeline:
            pps = bucket.get("pps", 0)
            ts = bucket.get("timestamp", 0)
            if pps > self.packet_rate_threshold:
                if self._can_fire("PACKET_RATE_SPIKE", "global", ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Packet Rate Spike",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "host": "Network Broadcaster",
                        "observed_metric": f"{pps} pps",
                        "configured_threshold": f"{self.packet_rate_threshold} pps",
                        "explanation": f"Observed traffic rate of {pps} packets/sec exceeded the threshold of {self.packet_rate_threshold} pps.",
                        "evidence": {"observed_pps": pps, "bucket_timestamp": ts},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

            # Rule 4: Throughput Spike
            kbps = bucket.get("kbps", 0)
            threshold_kbps = (self.byte_rate_threshold * 8) / 1000.0
            if kbps > threshold_kbps:
                if self._can_fire("THROUGHPUT_SPIKE", "global", ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Bandwidth Utilization Spike",
                        "severity": "LOW",
                        "timestamp": ts,
                        "host": "Network Segment",
                        "observed_metric": f"{kbps} kbps",
                        "configured_threshold": f"{threshold_kbps} kbps",
                        "explanation": f"Traffic bandwidth of {kbps} kbps exceeded configured baseline of {threshold_kbps} kbps.",
                        "evidence": {"observed_kbps": kbps, "bucket_timestamp": ts},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # Rule 5: Dominant Host / Traffic Monopoly
        total_packets = analytics_summary.get("total_packets", 0)
        if total_packets >= 50:
            sources = top_talkers.get("sources", [])
            for src in sources:
                src_pkts = src.get("packets", 0)
                ratio = src_pkts / total_packets
                if ratio > self.host_volume_ratio:
                    src_ip = src.get("ip", "Unknown")
                    if self._can_fire("DOMINANT_HOST", src_ip, 0.0):
                        alert = {
                            "alert_id": f"ALT-{len(self.alerts) + 1}",
                            "alert_type": "Dominant Traffic Host",
                            "severity": "LOW",
                            "timestamp": analytics_summary.get("capture_duration_seconds", 0),
                            "host": src_ip,
                            "observed_metric": f"{round(ratio * 100, 1)}% of total packets ({src_pkts}/{total_packets})",
                            "configured_threshold": f"> {round(self.host_volume_ratio * 100, 1)}%",
                            "explanation": f"Host {src_ip} accounts for {round(ratio * 100, 1)}% of all observed session traffic.",
                            "evidence": {"source_ip": src_ip, "host_packets": src_pkts, "total_packets": total_packets},
                        }
                        self.alerts.append(alert)
                        new_alerts.append(alert)

        return new_alerts

    def get_all_alerts(self) -> list[dict]:
        return list(self.alerts)
