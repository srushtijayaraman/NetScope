"""
NetScope Capture Comparator Module
Performs comparative analysis between two PCAP/PCAPNG capture datasets.
Evaluates volume diffs, protocol shifts, throughput variances, host diversity,
flow counts, and security alert deltas with zero-denominator safety.
Detects disparate capture durations and emits methodological warnings.
"""

import os
from capture.pcap_reader import OfflinePcapProcessor, PcapReaderError
from analyzer.flow_tracker import FlowTracker
from analytics.statistics import TrafficAnalytics
from analytics.anomaly_detector import AnomalyDetector


def analyze_standalone_pcap(filepath: str, capture_id: str = "comparison") -> dict:
    """
    Parses a PCAP file in an isolated sandbox without mutating global session state.
    Returns summary, protocols, flows, alerts, and talkers.
    """
    if not os.path.exists(filepath):
        raise PcapReaderError(f"Capture file not found: {filepath}")

    analytics = TrafficAnalytics()
    flow_tracker = FlowTracker()
    detector = AnomalyDetector()
    processor = OfflinePcapProcessor(max_packets_memory=5000)

    def _cb(record):
        analytics.ingest_packet(record)
        flow_tracker.process_packet(record)
        detector.evaluate_packet(record)

    res = processor.process_file(filepath, capture_id=capture_id, packet_callback=_cb)
    analytics.processing_time_sec = res.get("processing_time_seconds", 0.0)

    summary = analytics.get_summary()
    summary["active_flows"] = flow_tracker.get_flow_count()
    summary["file_size_bytes"] = res.get("file_size_bytes", 0)
    summary["filename"] = os.path.basename(filepath)

    timeline = analytics.get_traffic_timeline()
    top_talkers = analytics.get_top_talkers()
    detector.evaluate_batch_statistics(summary, timeline, top_talkers)

    return {
        "summary": summary,
        "protocols": analytics.get_protocol_distribution(),
        "top_talkers": top_talkers,
        "flows_count": flow_tracker.get_flow_count(),
        "top_flows": flow_tracker.get_top_flows(limit=5),
        "alerts": detector.get_all_alerts(),
    }


def compute_metric_diff(val_a: float | int, val_b: float | int, round_digits: int = 2) -> dict:
    """Calculates absolute delta and percentage change with zero-denominator guard."""
    diff = val_b - val_a
    if val_a == 0:
        pct_change = 0.0 if val_b == 0 else (100.0 if val_b > 0 else -100.0)
    else:
        pct_change = round((diff / val_a) * 100.0, round_digits)

    return {
        "val_a": round(val_a, round_digits) if isinstance(val_a, float) else val_a,
        "val_b": round(val_b, round_digits) if isinstance(val_b, float) else val_b,
        "diff": round(diff, round_digits) if isinstance(diff, float) else diff,
        "pct_change": pct_change,
    }


def compare_captures(data_a: dict, data_b: dict, label_a: str = "Capture A", label_b: str = "Capture B") -> dict:
    """
    Compares two analyzed capture datasets.
    Generates comparative metrics, protocol distribution deltas, alert differences,
    and methodological validity warnings.
    """
    sum_a = data_a.get("summary", {})
    sum_b = data_b.get("summary", {})

    dur_a = sum_a.get("capture_duration_seconds", 0.0)
    dur_b = sum_b.get("capture_duration_seconds", 0.0)

    # Methodological check: disparate duration warning
    duration_warning = None
    if dur_a > 0 and dur_b > 0:
        ratio = max(dur_a, dur_b) / min(dur_a, dur_b)
        if ratio >= 2.0 and abs(dur_a - dur_b) >= 2.0:
            duration_warning = (
                f"Caution: Observation spans differ significantly ({dur_a:.2f}s vs {dur_b:.2f}s, ratio {ratio:.1f}x). "
                f"Direct rate and throughput comparisons may be skewed by the unequal measurement windows."
            )
    elif (dur_a == 0.0 and dur_b > 0.0) or (dur_b == 0.0 and dur_a > 0.0):
        duration_warning = "Caution: One capture has zero recorded duration (single packet or clock anomaly)."

    # Key metric comparisons
    metrics = {
        "total_packets": compute_metric_diff(sum_a.get("total_packets", 0), sum_b.get("total_packets", 0)),
        "total_bytes": compute_metric_diff(sum_a.get("total_bytes", 0), sum_b.get("total_bytes", 0)),
        "capture_duration_seconds": compute_metric_diff(dur_a, dur_b),
        "capture_pps": compute_metric_diff(sum_a.get("capture_pps", 0.0), sum_b.get("capture_pps", 0.0)),
        "throughput_kbps": compute_metric_diff(sum_a.get("throughput_kbps", 0.0), sum_b.get("throughput_kbps", 0.0)),
        "average_packet_size_bytes": compute_metric_diff(sum_a.get("average_packet_size_bytes", 0.0), sum_b.get("average_packet_size_bytes", 0.0)),
        "unique_hosts": compute_metric_diff(sum_a.get("unique_hosts", 0), sum_b.get("unique_hosts", 0)),
        "active_flows": compute_metric_diff(sum_a.get("active_flows", 0), sum_b.get("active_flows", 0)),
        "alerts_count": compute_metric_diff(len(data_a.get("alerts", [])), len(data_b.get("alerts", []))),
        "processing_time_seconds": compute_metric_diff(sum_a.get("processing_time_seconds", 0.0), sum_b.get("processing_time_seconds", 0.0), round_digits=4),
        "processing_pps": compute_metric_diff(sum_a.get("processing_pps", 0.0), sum_b.get("processing_pps", 0.0)),
    }

    # Protocol comparison (Transport & Network)
    proto_a = data_a.get("protocols", {})
    proto_b = data_b.get("protocols", {})

    def _compare_layer(layer_key: str):
        layer_a = proto_a.get(layer_key, {})
        layer_b = proto_b.get(layer_key, {})
        all_keys = set(layer_a.keys()) | set(layer_b.keys())
        comp = []
        for k in sorted(all_keys):
            ca = layer_a.get(k, {}).get("count", 0)
            pa = layer_a.get(k, {}).get("percentage", 0.0)
            cb = layer_b.get(k, {}).get("count", 0)
            pb = layer_b.get(k, {}).get("percentage", 0.0)
            comp.append({
                "protocol": k,
                "count_a": ca,
                "pct_a": pa,
                "count_b": cb,
                "pct_b": pb,
                "count_diff": cb - ca,
                "pct_diff": round(pb - pa, 2),
            })
        return comp

    protocol_shifts = {
        "transport": _compare_layer("transport"),
        "network": _compare_layer("network"),
        "application": _compare_layer("application"),
    }

    # Alert severity comparison
    def _alert_counts(alerts_list):
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts_list:
            sev = a.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    alerts_a_counts = _alert_counts(data_a.get("alerts", []))
    alerts_b_counts = _alert_counts(data_b.get("alerts", []))
    alerts_comparison = {
        "HIGH": compute_metric_diff(alerts_a_counts["HIGH"], alerts_b_counts["HIGH"], round_digits=0),
        "MEDIUM": compute_metric_diff(alerts_a_counts["MEDIUM"], alerts_b_counts["MEDIUM"], round_digits=0),
        "LOW": compute_metric_diff(alerts_a_counts["LOW"], alerts_b_counts["LOW"], round_digits=0),
    }

    return {
        "capture_a": {
            "label": label_a,
            "filename": sum_a.get("filename", "Capture A"),
            "file_size_bytes": sum_a.get("file_size_bytes", 0),
            "summary": sum_a,
        },
        "capture_b": {
            "label": label_b,
            "filename": sum_b.get("filename", "Capture B"),
            "file_size_bytes": sum_b.get("file_size_bytes", 0),
            "summary": sum_b,
        },
        "metrics": metrics,
        "protocol_shifts": protocol_shifts,
        "alerts_comparison": alerts_comparison,
        "duration_warning": duration_warning,
    }
