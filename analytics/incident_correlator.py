"""
NetScope X Security Incident Correlator
Correlates raw heuristic and volumetric alerts into deduplicated, actionable security incidents.
Preserves forensic evidence references (packet IDs, flow IDs) and distinguishes observable
network facts from heuristic attack hypotheses.
"""

import time
from collections import OrderedDict


INCIDENT_SEVERITY_RATIONALES = {
    "DENIAL_OF_SERVICE": "Repeated unacknowledged SYN frames or rate floods exhaust OS connection backlog queues and state tables.",
    "RECONNAISSANCE": "Rapid multi-port queries indicate systematic discovery probing to locate accessible listening services.",
    "VOLUMETRIC_ANOMALY": "Packet rate bursts significantly exceeding baseline thresholds may indicate volumetric flooding or misconfigured automation.",
    "THROUGHPUT_ANOMALY": "Bandwidth saturation exceeding provisioned link budgets may cause packet buffering and elevated latency.",
    "RESOURCE_MONOPOLIZATION": "A single host generating >50% of total capture traffic can indicate unauthorized bulk exfiltration or automated sync.",
}

BENIGN_EXPLANATIONS = {
    "DENIAL_OF_SERVICE": "Aggressive application reconnection retries against an offline or firewalled internal microservice; client load testing.",
    "RECONNAISSANCE": "Vulnerability assessment scanners (Nessus, OpenVAS), multi-service health checking daemons, or active discovery protocols.",
    "VOLUMETRIC_ANOMALY": "Scheduled bulk backup, database replication snapshot, large software update distribution, or network file transfer.",
    "THROUGHPUT_ANOMALY": "High-definition video streaming, legitimate OS image deployment, or VM backup synchronization.",
    "RESOURCE_MONOPOLIZATION": "Primary network gateway, proxy server, or active database host serving legitimate concurrent user requests.",
}


class IncidentCorrelator:
    def __init__(self, correlation_window_sec: float = 60.0):
        self.correlation_window_sec = correlation_window_sec
        self.incidents = OrderedDict()  # incident_id -> dict
        self._key_to_id = {}           # correlation_key -> incident_id
        self._next_id = 1

    def reset(self):
        self.incidents.clear()
        self._key_to_id.clear()
        self._next_id = 1

    def correlate_alert(self, alert: dict, capture_id: str = "default", related_flows: list[str] = None) -> dict:
        """
        Correlates a raw detection alert into a structured Incident.
        Updates an existing active incident if matching the same category, source, and target within the time window.
        """
        alert_type = alert.get("alert_type", "")
        host = alert.get("host", "Unknown")
        target = alert.get("target", "Unknown")
        ts = float(alert.get("timestamp", 0.0))
        if ts <= 0:
            ts = time.time()

        # Categorize
        if "SYN" in alert_type:
            category = "DENIAL_OF_SERVICE"
            rule_name = "TCP SYN Burst / Half-Open Connection Flood"
            severity = alert.get("severity") or "HIGH"
        elif "Port Scan" in alert_type or "Multi-Port" in alert_type:
            category = "RECONNAISSANCE"
            rule_name = "Multi-Port Reconnaissance / Port Scan"
            severity = alert.get("severity") or "MEDIUM"
        elif "Packet Rate" in alert_type or "PPS" in alert_type:
            category = "VOLUMETRIC_ANOMALY"
            rule_name = "Volumetric Packet Rate Spike"
            severity = alert.get("severity") or "MEDIUM"
        elif "Bandwidth" in alert_type or "Throughput" in alert_type:
            category = "THROUGHPUT_ANOMALY"
            rule_name = "High Bandwidth Throughput Saturation"
            severity = alert.get("severity") or "LOW"
        else:
            category = "RESOURCE_MONOPOLIZATION"
            rule_name = "Dominant Host Traffic Volume Share"
            severity = alert.get("severity") or "LOW"

        packet_refs = list(alert.get("packet_references", []))
        flow_refs = list(related_flows or [])
        alert_evidence = alert.get("evidence", {})

        # Correlation Key: (category, host, target)
        corr_key = (category, host, target)
        existing_id = self._key_to_id.get(corr_key)

        if existing_id and existing_id in self.incidents:
            inc = self.incidents[existing_id]
            # Check correlation window
            if (ts - inc["last_seen"]) <= self.correlation_window_sec:
                # Merge evidence
                inc["last_seen"] = max(inc["last_seen"], ts)
                inc["duration_sec"] = round(inc["last_seen"] - inc["first_seen"], 2)
                inc["hit_count"] += 1
                inc["observed_value"] = alert.get("observed_value") or inc["observed_value"]
                
                # Merge packet IDs preserving unique order up to 50
                existing_pids = set(inc["evidence"]["packet_ids"])
                for pid in packet_refs:
                    if pid not in existing_pids:
                        inc["evidence"]["packet_ids"].append(pid)
                        existing_pids.add(pid)
                if len(inc["evidence"]["packet_ids"]) > 50:
                    inc["evidence"]["packet_ids"] = inc["evidence"]["packet_ids"][-50:]

                # Merge flow IDs
                existing_fids = set(inc["evidence"]["flow_ids"])
                for fid in flow_refs:
                    if fid not in existing_fids:
                        inc["evidence"]["flow_ids"].append(fid)
                        existing_fids.add(fid)

                inc["evidence"]["hit_count"] = inc["hit_count"]
                inc["evidence"]["latest_alert_raw"] = alert_type
                return inc

        # Create new incident
        inc_id = f"INC-{self._next_id:04d}"
        self._next_id += 1

        incident = {
            "incident_id": inc_id,
            "capture_id": capture_id,
            "category": category,
            "rule_name": rule_name,
            "severity": severity,
            "severity_rationale": INCIDENT_SEVERITY_RATIONALES.get(category, "Unusual traffic pattern observed."),
            "status": "New",
            "first_seen": ts,
            "last_seen": ts,
            "duration_sec": 0.0,
            "hit_count": 1,
            "source_host": host,
            "target_host": target,
            "observed_value": alert.get("observed_value") or alert.get("observed_metric") or "Observed anomalous activity",
            "configured_threshold": alert.get("configured_threshold") or alert.get("threshold") or "N/A",
            "observation_window": alert.get("time_window", "Sliding window"),
            "explanation": alert.get("explanation", ""),
            "benign_explanation": BENIGN_EXPLANATIONS.get(category, "Benign operational activity on local network."),
            "analyst_notes": "",
            "evidence": {
                "packet_ids": packet_refs[:50],
                "flow_ids": flow_refs[:20],
                "hit_count": 1,
                "initial_alert": alert_type,
                "classification_nature": alert.get("classification_nature", "Heuristic"),
                "details": alert_evidence,
            }
        }

        self.incidents[inc_id] = incident
        self._key_to_id[corr_key] = inc_id
        return incident

    def get_all_incidents(self, status: str = None, severity: str = None, host: str = None) -> list[dict]:
        """Returns filtered incidents in reverse chronological order."""
        res = []
        for inc in reversed(self.incidents.values()):
            if status and inc.get("status", "").lower() != status.lower():
                continue
            if severity and inc.get("severity", "").upper() != severity.upper():
                continue
            if host:
                h_lower = host.lower()
                if h_lower not in inc.get("source_host", "").lower() and h_lower not in inc.get("target_host", "").lower():
                    continue
            res.append(inc)
        return res

    def get_incident(self, incident_id: str) -> dict | None:
        return self.incidents.get(incident_id)

    def update_status(self, incident_id: str, new_status: str, notes: str = None) -> dict | None:
        if incident_id in self.incidents:
            self.incidents[incident_id]["status"] = new_status
            if notes is not None:
                self.incidents[incident_id]["analyst_notes"] = notes
            return self.incidents[incident_id]
        return None
