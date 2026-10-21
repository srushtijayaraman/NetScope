"""
NetScope Rule-Based Anomaly Detection Module
Evaluates deterministic network traffic heuristics:
1. Suspicious TCP SYN bursts (heuristic: potential SYN flood)
2. Rapid multi-port query patterns (heuristic: potential vertical or horizontal port scan)
3. Volumetric packet rate spikes (observable fact: threshold exceeded in time bucket)
4. Throughput bandwidth surges (observable fact: bandwidth threshold exceeded)
5. Dominant host traffic share (observable fact: single host generating majority volume)

Strictly distinguishes observable facts from heuristic suspicions.
Attaches packet references, time windows, and supporting evidence to every alert.
Supports dynamic threshold reconfiguration and cooldown deduplication.
"""

from collections import defaultdict, deque


class AnomalyDetector:
    def __init__(self, config=None):
        self.packet_rate_threshold = int(getattr(config, "PACKET_RATE_THRESHOLD", 150))
        self.byte_rate_threshold = int(getattr(config, "BYTE_RATE_THRESHOLD", 500_000))
        self.syn_flood_threshold = int(getattr(config, "SYN_FLOOD_THRESHOLD", 20))
        self.port_scan_threshold = int(getattr(config, "PORT_SCAN_THRESHOLD", 15))
        self.host_volume_ratio = float(getattr(config, "HOST_VOLUME_RATIO_THRESHOLD", 0.5))
        self.cooldown_sec = int(getattr(config, "ANOMALY_COOLDOWN_SECONDS", 10))

        self.alerts = []
        self._last_alert_time = {}  # (alert_type, target) -> timestamp
        
        # Sliding window state
        # src_ip -> deque of (timestamp, packet_id)
        self._syn_history = defaultdict(deque)
        # src_ip -> deque of (timestamp, dst_ip, dport, packet_id)
        self._port_scan_history = defaultdict(deque)

    def get_thresholds(self) -> dict:
        """Returns the active threshold configuration."""
        return {
            "packet_rate_threshold": self.packet_rate_threshold,
            "byte_rate_threshold": self.byte_rate_threshold,
            "syn_flood_threshold": self.syn_flood_threshold,
            "port_scan_threshold": self.port_scan_threshold,
            "host_volume_ratio": self.host_volume_ratio,
            "cooldown_seconds": self.cooldown_sec,
        }

    def update_thresholds(self, new_cfg: dict) -> dict:
        """Dynamically reconfigures thresholds with input validation."""
        if "packet_rate_threshold" in new_cfg:
            self.packet_rate_threshold = max(10, int(new_cfg["packet_rate_threshold"]))
        if "byte_rate_threshold" in new_cfg:
            self.byte_rate_threshold = max(1000, int(new_cfg["byte_rate_threshold"]))
        if "syn_flood_threshold" in new_cfg:
            self.syn_flood_threshold = max(3, int(new_cfg["syn_flood_threshold"]))
        if "port_scan_threshold" in new_cfg:
            self.port_scan_threshold = max(3, int(new_cfg["port_scan_threshold"]))
        if "host_volume_ratio" in new_cfg:
            val = float(new_cfg["host_volume_ratio"])
            self.host_volume_ratio = min(1.0, max(0.1, val))
        if "cooldown_seconds" in new_cfg:
            self.cooldown_sec = max(1, int(new_cfg["cooldown_seconds"]))

        return self.get_thresholds()

    def reset(self):
        self.alerts.clear()
        self._last_alert_time.clear()
        self._syn_history.clear()
        self._port_scan_history.clear()

    def _can_fire(self, alert_type: str, target: str, current_ts: float) -> bool:
        """Enforces a cooldown to prevent repetitive alerting on identical flows."""
        key = (alert_type, target)
        last_time = self._last_alert_time.get(key)
        if last_time is None or (current_ts - last_time) >= self.cooldown_sec:
            self._last_alert_time[key] = current_ts
            return True
        return False

    def evaluate_packet(self, record: dict) -> list[dict]:
        """
        Evaluates a single packet for real-time stateful anomalies (SYN bursts, port scans).
        Returns a list of newly triggered alerts with supporting packet references.
        """
        new_alerts = []
        src_ip = record.get("source_ip")
        dst_ip = record.get("destination_ip")
        ts = record.get("timestamp", 0.0)
        proto = record.get("transport_protocol")
        flags = record.get("tcp_flags", [])
        dport = record.get("destination_port")
        pkt_id = record.get("packet_id")

        if not src_ip or ts <= 0:
            return new_alerts

        # Rule 1: Suspicious TCP SYN Burst (Heuristic: Potential SYN Flood)
        # Evaluates standalone SYN frames (without ACK) within a 5-second sliding window
        if proto == "TCP" and "SYN" in flags and "ACK" not in flags:
            history = self._syn_history[src_ip]
            history.append((ts, pkt_id))
            while history and (ts - history[0][0]) > 5.0:
                history.popleft()

            if len(history) >= self.syn_flood_threshold:
                if self._can_fire("SYN_BURST", src_ip, ts):
                    ref_ids = [pid for _, pid in history if pid is not None]
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Heuristic: Suspicious SYN Burst (Possible SYN Flood)",
                        "classification_nature": "Heuristic Suspicion (Unconfirmed)",
                        "severity": "HIGH",
                        "timestamp": ts,
                        "host": src_ip,
                        "target": dst_ip,
                        "observed_value": f"{len(history)} standalone SYNs",
                        "threshold": f"{self.syn_flood_threshold} SYNs in 5.0s window",
                        "time_window": "5.0s sliding window",
                        "explanation": (
                            f"Observed {len(history)} standalone TCP SYN frames from host {src_ip} within 5.0 seconds. "
                            f"While consistent with half-open SYN flood behavior, this may also indicate connection retries to an unresponsive service."
                        ),
                        "packet_references": ref_ids[-25:],  # Keep recent 25 packet IDs
                        "evidence": {
                            "source_ip": src_ip,
                            "target_ip": dst_ip,
                            "syn_count": len(history),
                            "window_seconds": 5.0,
                            "first_packet_id": ref_ids[0] if ref_ids else None,
                            "latest_packet_id": ref_ids[-1] if ref_ids else None,
                        },
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # Rule 2: Multi-Port Query Pattern (Heuristic: Potential Port Scan)
        # Evaluates distinct destination ports queried by a single source within a 5-second window
        if proto in ("TCP", "UDP") and dport is not None:
            scan_hist = self._port_scan_history[src_ip]
            scan_hist.append((ts, dst_ip, dport, pkt_id))
            while scan_hist and (ts - scan_hist[0][0]) > 5.0:
                scan_hist.popleft()

            unique_ports = {item[2] for item in scan_hist}
            if len(unique_ports) >= self.port_scan_threshold:
                if self._can_fire("PORT_SCAN", src_ip, ts):
                    ref_ids = [item[3] for item in scan_hist if item[3] is not None]
                    # Identify whether targeting single IP (vertical) or multiple (horizontal)
                    unique_targets = {item[1] for item in scan_hist if item[1]}
                    scan_type = "Vertical Scan (Single Host)" if len(unique_targets) == 1 else "Horizontal / Distributed Scan"
                    
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": f"Heuristic: Potential Port Scan / Multi-Port Probe ({scan_type})",
                        "classification_nature": "Heuristic Suspicion (Unconfirmed)",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "host": src_ip,
                        "target": dst_ip if len(unique_targets) == 1 else f"{len(unique_targets)} Distinct Hosts",
                        "observed_value": f"{len(unique_ports)} distinct ports probed",
                        "threshold": f"{self.port_scan_threshold} ports in 5.0s window",
                        "time_window": "5.0s sliding window",
                        "explanation": (
                            f"Host {src_ip} queried {len(unique_ports)} distinct destination ports within 5.0 seconds ({scan_type}). "
                            f"This pattern is characteristic of automated port reconnaissance, but can also occur with misconfigured multi-service applications."
                        ),
                        "packet_references": ref_ids[-25:],
                        "evidence": {
                            "source_ip": src_ip,
                            "unique_ports_count": len(unique_ports),
                            "sample_ports": sorted(list(unique_ports))[:10],
                            "window_seconds": 5.0,
                            "targets_count": len(unique_targets),
                        },
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        return new_alerts

    def evaluate_batch_statistics(self, analytics_summary: dict, timeline: list[dict], top_talkers: dict) -> list[dict]:
        """
        Evaluates session-wide volumetric anomalies across timeline buckets and host distributions.
        Distinguishes confirmed mathematical observations from heuristic suspicions.
        """
        new_alerts = []

        # Rule 3: High Packet Rate Spike (Observable Fact)
        for bucket in timeline:
            pps = bucket.get("pps", 0)
            ts = bucket.get("timestamp", 0)
            if pps > self.packet_rate_threshold:
                if self._can_fire("PACKET_RATE_SPIKE", "global", ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Observation: Volumetric Packet Rate Spike",
                        "classification_nature": "Observable Traffic Fact",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "host": "Monitored Segment",
                        "target": "Broadcast / Multicast / Unicast",
                        "observed_value": f"{pps} PPS",
                        "threshold": f"{self.packet_rate_threshold} PPS",
                        "time_window": "1.0s interval bucket",
                        "explanation": (
                            f"Measured packet arrival rate of {pps} packets/sec exceeded baseline threshold of {self.packet_rate_threshold} PPS. "
                            f"Indicates a burst of network activity or high-volume file transfer."
                        ),
                        "packet_references": [],
                        "evidence": {"observed_pps": pps, "bucket_timestamp": ts},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

            # Rule 4: Bandwidth Throughput Surge (Observable Fact)
            kbps = bucket.get("kbps", 0)
            threshold_kbps = (self.byte_rate_threshold * 8) / 1000.0
            if kbps > threshold_kbps:
                if self._can_fire("THROUGHPUT_SPIKE", "global", ts):
                    alert = {
                        "alert_id": f"ALT-{len(self.alerts) + 1}",
                        "alert_type": "Observation: High Bandwidth Utilization",
                        "classification_nature": "Observable Traffic Fact",
                        "severity": "LOW",
                        "timestamp": ts,
                        "host": "Monitored Link",
                        "target": "Aggregate Traffic",
                        "observed_value": f"{kbps} kbps",
                        "threshold": f"{threshold_kbps} kbps (Byte threshold: {self.byte_rate_threshold} B/s)",
                        "time_window": "1.0s interval bucket",
                        "explanation": (
                            f"Observed link throughput reached {kbps} kbps, exceeding the configured baseline of {threshold_kbps} kbps."
                        ),
                        "packet_references": [],
                        "evidence": {"observed_kbps": kbps, "bucket_timestamp": ts},
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # Rule 5: Dominant Host Traffic Share (Observable Fact)
        total_packets = analytics_summary.get("total_packets", 0)
        if total_packets >= 50:
            sources = top_talkers.get("sources", [])
            for src in sources:
                src_pkts = src.get("packets", 0)
                ratio = src_pkts / total_packets
                if ratio > self.host_volume_ratio:
                    src_ip = src.get("ip", "Unknown")
                    if self._can_fire("DOMINANT_HOST", src_ip, 0.0):
                        pct = round(ratio * 100, 1)
                        alert = {
                            "alert_id": f"ALT-{len(self.alerts) + 1}",
                            "alert_type": "Observation: Dominant Traffic Host Share",
                            "classification_nature": "Observable Traffic Fact",
                            "severity": "LOW",
                            "timestamp": analytics_summary.get("capture_duration_seconds", 0),
                            "host": src_ip,
                            "target": "Session Endpoints",
                            "observed_value": f"{pct}% of total traffic ({src_pkts}/{total_packets} pkts)",
                            "threshold": f"> {round(self.host_volume_ratio * 100, 1)}%",
                            "time_window": "Full Capture Session",
                            "explanation": (
                                f"Host {src_ip} accounts for {pct}% of all recorded packets in this capture. "
                                f"Typical of a central gateway, primary web server, or active streaming source."
                            ),
                            "packet_references": [],
                            "evidence": {"source_ip": src_ip, "host_packets": src_pkts, "total_packets": total_packets},
                        }
                        self.alerts.append(alert)
                        new_alerts.append(alert)

        return new_alerts

    def get_all_alerts(self) -> list[dict]:
        return list(self.alerts)
