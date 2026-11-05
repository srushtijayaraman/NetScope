"""
NetScope REST API Endpoints
Implements clean, predictable JSON endpoints with full input validation,
server-side filtering, pagination, CSV export, and capture lifecycle control.
"""

import os
import io
import csv
import time
import uuid
from flask import Blueprint, request, jsonify, Response, current_app
from werkzeug.utils import secure_filename

import scapy
from capture.pcap_reader import OfflinePcapProcessor, PcapReaderError
from capture.live_capture import LiveCaptureManager, get_available_interfaces, check_live_capture_capability
from analyzer.parser import parse_packet
from analyzer.flow_tracker import FlowTracker
from analytics.statistics import TrafficAnalytics
from analytics.anomaly_detector import AnomalyDetector
from analytics.incident_correlator import IncidentCorrelator
from analytics.topology import build_network_topology
from analytics.investigation_manager import generate_case_html_report
from analytics.capture_comparator import compare_captures, analyze_standalone_pcap
from analytics.report_generator import generate_html_report
from capture.replay_engine import ReplayEngine, SCENARIO_METADATA
from storage.database import DatabaseManager

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Session state containers (Thread-safe lock where appropriate)
import threading
session_lock = threading.Lock()

active_session = {
    "capture_id": None,
    "filename": None,
    "mode": "none",
    "packets": [],
    "analytics": TrafficAnalytics(),
    "flow_tracker": FlowTracker(),
    "anomaly_detector": None,
    "incident_correlator": IncidentCorrelator(),
}

live_manager = LiveCaptureManager()
replay_engine = ReplayEngine()


def get_db():
    try:
        db_path = current_app.config.get("DATABASE_PATH", "storage/netscope.db")
    except RuntimeError:
        db_path = "storage/netscope.db"
    return DatabaseManager(db_path)


def get_detector():
    if active_session["anomaly_detector"] is None:
        try:
            cfg = current_app.config
        except RuntimeError:
            cfg = None
        active_session["anomaly_detector"] = AnomalyDetector(cfg)
    return active_session["anomaly_detector"]


def reset_active_session(capture_id: str, filename: str, mode: str):
    with session_lock:
        active_session["capture_id"] = capture_id
        active_session["filename"] = filename
        active_session["mode"] = mode
        active_session["packets"].clear()
        active_session["analytics"].reset()
        active_session["flow_tracker"].reset()
        detector = get_detector()
        detector.reset()
        if "incident_correlator" in active_session and active_session["incident_correlator"]:
            active_session["incident_correlator"].reset()


def on_packet_received(record: dict):
    """Callback used by offline reader, live capture worker, and replay lab."""
    with session_lock:
        active_session["analytics"].ingest_packet(record)
        active_session["flow_tracker"].process_packet(record)
        
        # Real-time stateful alerts (SYN flood, Port scan)
        detector = get_detector()
        new_alerts = detector.evaluate_packet(record)
        if new_alerts:
            db = get_db()
            correlator = active_session.get("incident_correlator")
            fid = record.get("flow_id")
            related_flows = [fid] if fid else []
            for alt in new_alerts:
                db.save_alert(active_session["capture_id"] or "live", alt)
                if correlator:
                    inc = correlator.correlate_alert(alt, capture_id=active_session["capture_id"] or "live", related_flows=related_flows)
                    db.upsert_incident(inc)

        # Retain bounded packet history in memory for table exploration
        try:
            max_pkts = current_app.config.get("MAX_MEMORY_PACKETS", 10000)
        except RuntimeError:
            max_pkts = 10000
        if len(active_session["packets"]) < max_pkts:
            active_session["packets"].append(record)


@api_bp.route("/health", methods=["GET"])
def health():
    cap_check = check_live_capture_capability()
    return jsonify({
        "status": "ok",
        "service": "NetScope",
        "version": "1.0.0",
        "scapy_version": scapy.__version__,
        "live_capture_supported": cap_check["supported"],
        "live_capture_info": cap_check["reason"],
    })


@api_bp.route("/interfaces", methods=["GET"])
def list_interfaces():
    cap_check = check_live_capture_capability()
    ifaces = get_available_interfaces()
    return jsonify({
        "supported": cap_check["supported"],
        "message": cap_check["reason"],
        "solution": cap_check.get("solution"),
        "interfaces": ifaces,
    })


@api_bp.route("/captures/upload", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    allowed = current_app.config.get("ALLOWED_EXTENSIONS", {"pcap", "pcapng", "cap"})

    if ext not in allowed:
        return jsonify({
            "error": f"Invalid file extension '.{ext}'. Allowed: {', '.join(allowed)}"
        }), 400

    upload_dir = current_app.config.get("UPLOAD_FOLDER", "data/uploads")
    os.makedirs(upload_dir, exist_ok=True)
    capture_id = f"cap-{uuid.uuid4().hex[:8]}"
    saved_path = os.path.join(upload_dir, f"{capture_id}_{filename}")
    
    file.save(saved_path)

    # Process offline PCAP
    reset_active_session(capture_id, filename, "offline")
    processor = OfflinePcapProcessor(max_packets_memory=current_app.config.get("MAX_MEMORY_PACKETS", 10000))

    try:
        result = processor.process_file(
            saved_path,
            capture_id=capture_id,
            packet_callback=on_packet_received,
        )
    except PcapReaderError as err:
        return jsonify({"error": str(err)}), 422
    except Exception as exc:
        return jsonify({"error": f"Internal parser error: {str(exc)}"}), 500

    # Evaluate batch anomalies (rates, dominant hosts)
    with session_lock:
        active_session["analytics"].processing_time_sec = result["processing_time_seconds"]
        summary = active_session["analytics"].get_summary()
        timeline = active_session["analytics"].get_traffic_timeline()
        talkers = active_session["analytics"].get_top_talkers()
        
        detector = get_detector()
        batch_alerts = detector.evaluate_batch_statistics(summary, timeline, talkers)
        
        # Persist session and alerts in database
        db = get_db()
        db.record_session(
            capture_id=capture_id,
            filename=filename,
            mode="offline",
            packet_count=result["packets_processed"],
            byte_count=summary["total_bytes"],
            duration_seconds=summary["capture_duration_seconds"],
            status="COMPLETED",
        )
        db.save_summary(capture_id, summary)
        correlator = active_session.get("incident_correlator")
        for alt in batch_alerts:
            db.save_alert(capture_id, alt)
            if correlator:
                inc = correlator.correlate_alert(alt, capture_id=capture_id)
                db.upsert_incident(inc)

    return jsonify({
        "success": True,
        "message": f"Successfully parsed {result['packets_processed']} packets.",
        "capture_id": capture_id,
        "filename": filename,
        "processing_time_seconds": result["processing_time_seconds"],
        "processing_pps": result["processing_pps"],
        "summary": summary,
    }), 201


@api_bp.route("/captures/load-sample", methods=["POST"])
def load_sample():
    """Loads a pre-generated sample PCAP from data/sample_traffic.pcap."""
    sample_path = os.path.join(current_app.config.get("BASE_DIR", "."), "data", "sample_traffic.pcap")
    if not os.path.exists(sample_path):
        return jsonify({"error": "Sample PCAP file not found. Generate it first."}), 404

    capture_id = f"sample-{uuid.uuid4().hex[:6]}"
    filename = "sample_traffic.pcap"
    reset_active_session(capture_id, filename, "offline")

    processor = OfflinePcapProcessor(max_packets_memory=current_app.config.get("MAX_MEMORY_PACKETS", 10000))
    try:
        result = processor.process_file(
            sample_path,
            capture_id=capture_id,
            packet_callback=on_packet_received,
        )
    except Exception as exc:
        return jsonify({"error": f"Failed to load sample PCAP: {str(exc)}"}), 500

    with session_lock:
        active_session["analytics"].processing_time_sec = result["processing_time_seconds"]
        summary = active_session["analytics"].get_summary()
        timeline = active_session["analytics"].get_traffic_timeline()
        talkers = active_session["analytics"].get_top_talkers()
        
        detector = get_detector()
        batch_alerts = detector.evaluate_batch_statistics(summary, timeline, talkers)
        
        db = get_db()
        db.record_session(
            capture_id=capture_id,
            filename=filename,
            mode="offline",
            packet_count=result["packets_processed"],
            byte_count=summary["total_bytes"],
            duration_seconds=summary["capture_duration_seconds"],
            status="COMPLETED",
        )
        db.save_summary(capture_id, summary)
        correlator = active_session.get("incident_correlator")
        for alt in batch_alerts:
            db.save_alert(capture_id, alt)
            if correlator:
                inc = correlator.correlate_alert(alt, capture_id=capture_id)
                db.upsert_incident(inc)

    return jsonify({
        "success": True,
        "message": f"Loaded sample PCAP with {result['packets_processed']} packets.",
        "capture_id": capture_id,
        "filename": filename,
        "summary": summary,
    })


@api_bp.route("/captures/reset", methods=["POST"])
def reset_session():
    """Clears the active capture session and resets all memory buffers."""
    reset_active_session(capture_id="", filename="", mode="idle")
    return jsonify({"success": True, "message": "Session reset successfully."})


@api_bp.route("/captures/start", methods=["POST"])
def start_live_capture():
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")

    capture_id = f"live-{uuid.uuid4().hex[:6]}"
    reset_active_session(capture_id, f"Live [{interface or 'Default'}]", "live")

    res = live_manager.start_capture(
        interface=interface,
        capture_id=capture_id,
        packet_callback=on_packet_received,
    )
    if not res.get("success"):
        return jsonify(res), 400

    return jsonify({
        "success": True,
        "message": res.get("message"),
        "capture_id": capture_id,
        "interface": interface,
    })


@api_bp.route("/captures/stop", methods=["POST"])
def stop_live_capture():
    res = live_manager.stop_capture()
    with session_lock:
        if active_session["capture_id"]:
            summary = active_session["analytics"].get_summary()
            db = get_db()
            db.record_session(
                capture_id=active_session["capture_id"],
                filename=active_session["filename"],
                mode="live",
                packet_count=summary["total_packets"],
                byte_count=summary["total_bytes"],
                duration_seconds=summary["capture_duration_seconds"],
                status="STOPPED",
            )
            db.save_summary(active_session["capture_id"], summary)

    return jsonify(res)


@api_bp.route("/captures/status", methods=["GET"])
def capture_status():
    live_st = live_manager.get_status()
    with session_lock:
        return jsonify({
            "active_mode": active_session["mode"],
            "capture_id": active_session["capture_id"],
            "filename": active_session["filename"],
            "packets_in_memory": len(active_session["packets"]),
            "live_status": live_st,
        })


@api_bp.route("/captures", methods=["GET"])
def get_historical_captures():
    db = get_db()
    sessions = db.get_sessions()
    return jsonify({"sessions": sessions})


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    with session_lock:
        summary = active_session["analytics"].get_summary()
        flow_count = active_session["flow_tracker"].get_flow_count()
        summary["active_flows"] = flow_count
        return jsonify(summary)


@api_bp.route("/protocols", methods=["GET"])
def get_protocols():
    with session_lock:
        dist = active_session["analytics"].get_protocol_distribution()
        return jsonify(dist)


@api_bp.route("/traffic-timeline", methods=["GET"])
def get_timeline():
    with session_lock:
        timeline = active_session["analytics"].get_traffic_timeline()
        return jsonify({"timeline": timeline})


@api_bp.route("/top-talkers", methods=["GET"])
def get_top_talkers():
    sort_by = request.args.get("sort_by", "bytes")
    limit = int(request.args.get("limit", 10))
    with session_lock:
        talkers = active_session["analytics"].get_top_talkers(limit=limit, sort_by=sort_by)
        top_ports = active_session["analytics"].get_top_ports(limit=limit)
        top_flows = active_session["flow_tracker"].get_top_flows(limit=limit, sort_by=sort_by)
        return jsonify({
            "talkers": talkers,
            "top_ports": top_ports,
            "top_flows": top_flows,
        })


@api_bp.route("/flows", methods=["GET"])
def get_flows():
    """Returns top active flows with summary statistics."""
    sort_by = request.args.get("sort_by", "bytes")
    limit = int(request.args.get("limit", 20))
    with session_lock:
        flows = active_session["flow_tracker"].get_top_flows(limit=limit, sort_by=sort_by)
        return jsonify({
            "total_flows": active_session["flow_tracker"].get_flow_count(),
            "flows": flows,
        })


@api_bp.route("/flows/<flow_id>", methods=["GET"])
def get_flow_detail(flow_id: str):
    """Returns detailed information for a specific flow including packet references."""
    with session_lock:
        flow = active_session["flow_tracker"].get_flow_by_id(flow_id)
        if not flow:
            return jsonify({"error": f"Flow '{flow_id}' not found."}), 404
        return jsonify(flow)


@api_bp.route("/flows/<flow_id>/timeline", methods=["GET"])
def get_flow_timeline(flow_id: str):
    """Returns chronological conversation progression events for a TCP/transport flow."""
    with session_lock:
        timeline_data = active_session["flow_tracker"].get_flow_timeline(flow_id)
        if not timeline_data:
            return jsonify({"error": f"Flow '{flow_id}' not found."}), 404
        return jsonify(timeline_data)


@api_bp.route("/alerts/config", methods=["GET", "POST"])
def alert_config():
    """Inspects or updates heuristic anomaly detection thresholds."""
    detector = get_detector()
    if request.method == "POST":
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body. Expected key-value object."}), 400
        updated = detector.update_thresholds(data)
        return jsonify({
            "success": True,
            "message": "Thresholds updated successfully.",
            "thresholds": updated,
        })
    return jsonify({"thresholds": detector.get_thresholds()})


@api_bp.route("/packets", methods=["GET"])
def get_packets():
    """
    Searchable, filterable, sortable, paginated packets list.
    Query parameters:
      - page (int, default 1)
      - limit (int, default 50)
      - search (str)
      - protocol (str)
      - src_ip (str)
      - dst_ip (str)
      - src_port (int)
      - dst_port (int)
      - packet_id (int)
      - flow_id (str)
      - sort_by (str)
      - sort_order (str, 'asc' or 'desc')
    """
    page = max(1, int(request.args.get("page", 1)))
    limit = min(200, max(1, int(request.args.get("limit", 50))))
    search = request.args.get("search", "").strip().lower()
    proto_filter = request.args.get("protocol", "").strip().upper()
    src_ip = request.args.get("src_ip", "").strip()
    dst_ip = request.args.get("dst_ip", "").strip()
    src_port = request.args.get("src_port", type=int)
    dst_port = request.args.get("dst_port", type=int)
    pkt_id_filter = request.args.get("packet_id", type=int)
    flow_id_filter = request.args.get("flow_id", "").strip()
    sort_by = request.args.get("sort_by", "packet_id")
    sort_order = request.args.get("sort_order", "asc").lower()

    with session_lock:
        packets = list(active_session["packets"])

    # Filtering
    filtered = []
    for p in packets:
        if pkt_id_filter is not None and p.get("packet_id") != pkt_id_filter:
            continue

        if flow_id_filter and p.get("flow_id") != flow_id_filter:
            continue

        if proto_filter and proto_filter not in (
            (p.get("transport_protocol") or "").upper(),
            (p.get("network_protocol") or "").upper(),
            (p.get("application_protocol") or "").upper(),
        ):
            continue

        if src_ip and p.get("source_ip") != src_ip:
            continue
        if dst_ip and p.get("destination_ip") != dst_ip:
            continue
        if src_port is not None and p.get("source_port") != src_port:
            continue
        if dst_port is not None and p.get("destination_port") != dst_port:
            continue

        if search:
            combined = f"{p.get('packet_id', '')} {p.get('source_ip', '')} {p.get('destination_ip', '')} {p.get('network_protocol', '')} {p.get('transport_protocol', '')} {p.get('application_protocol', '')} {p.get('summary', '')} {p.get('flow_id', '')}".lower()
            if search not in combined:
                continue

        filtered.append(p)

    # Sorting
    reverse = (sort_order == "desc")
    if sort_by in ("packet_id", "timestamp", "packet_length", "source_port", "destination_port"):
        filtered.sort(key=lambda x: (x.get(sort_by) is not None, x.get(sort_by) or 0), reverse=reverse)
    elif sort_by in ("source_ip", "destination_ip", "network_protocol", "transport_protocol", "application_protocol", "flow_id"):
        filtered.sort(key=lambda x: str(x.get(sort_by) or ""), reverse=reverse)

    total_count = len(filtered)
    total_pages = max(1, (total_count + limit - 1) // limit)
    start_idx = (page - 1) * limit
    paginated = filtered[start_idx : start_idx + limit]

    # Return slim representation for table performance
    slim_packets = []
    for p in paginated:
        slim_packets.append({
            "packet_id": p["packet_id"],
            "flow_id": p.get("flow_id"),
            "timestamp": p["timestamp"],
            "timestamp_iso": p["timestamp_iso"],
            "relative_time_sec": p.get("relative_time_sec", 0.0),
            "source_ip": p["source_ip"],
            "destination_ip": p["destination_ip"],
            "network_protocol": p["network_protocol"],
            "transport_protocol": p["transport_protocol"],
            "application_protocol": p["application_protocol"],
            "source_port": p["source_port"],
            "destination_port": p["destination_port"],
            "packet_length": p["packet_length"],
            "tcp_flags": p["tcp_flags"],
            "summary": p["summary"],
            "parsing_status": p["parsing_status"],
        })

    return jsonify({
        "total": total_count,
        "page": page,
        "limit": limit,
        "pages": total_pages,
        "packets": slim_packets,
    })


@api_bp.route("/packets/<int:packet_id>", methods=["GET"])
def get_packet_details(packet_id: int):
    with session_lock:
        for p in active_session["packets"]:
            if p["packet_id"] == packet_id:
                return jsonify(p)
    return jsonify({"error": f"Packet #{packet_id} not found."}), 404


@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    detector = get_detector()
    alerts = detector.get_all_alerts()
    return jsonify({"alerts": alerts})


@api_bp.route("/export/csv", methods=["GET"])
def export_csv():
    """Streams CSV of the active filtered dataset."""
    search = request.args.get("search", "").strip().lower()
    proto_filter = request.args.get("protocol", "").strip().upper()
    src_ip = request.args.get("src_ip", "").strip()
    dst_ip = request.args.get("dst_ip", "").strip()
    src_port = request.args.get("src_port", type=int)
    dst_port = request.args.get("dst_port", type=int)
    pkt_id_filter = request.args.get("packet_id", type=int)
    flow_id_filter = request.args.get("flow_id", "").strip()

    with session_lock:
        packets = list(active_session["packets"])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Packet ID",
        "Flow ID",
        "Timestamp (ISO)",
        "Timestamp (Epoch)",
        "Relative Time (s)",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Network Protocol",
        "Transport Protocol",
        "Application Protocol",
        "Length (Bytes)",
        "TCP Flags",
        "Status",
        "Summary",
    ])

    for p in packets:
        if pkt_id_filter is not None and p.get("packet_id") != pkt_id_filter:
            continue
        if flow_id_filter and p.get("flow_id") != flow_id_filter:
            continue
        if proto_filter and proto_filter not in (
            (p.get("transport_protocol") or "").upper(),
            (p.get("network_protocol") or "").upper(),
            (p.get("application_protocol") or "").upper(),
        ):
            continue
        if src_ip and p.get("source_ip") != src_ip:
            continue
        if dst_ip and p.get("destination_ip") != dst_ip:
            continue
        if src_port is not None and p.get("source_port") != src_port:
            continue
        if dst_port is not None and p.get("destination_port") != dst_port:
            continue
        if search:
            combined = f"{p.get('packet_id', '')} {p.get('source_ip', '')} {p.get('destination_ip', '')} {p.get('summary', '')} {p.get('flow_id', '')}".lower()
            if search not in combined:
                continue

        writer.writerow([
            p["packet_id"],
            p.get("flow_id") or "",
            p["timestamp_iso"],
            p["timestamp"],
            p.get("relative_time_sec", 0.0),
            p.get("source_ip") or "",
            p.get("destination_ip") or "",
            p.get("source_port") or "",
            p.get("destination_port") or "",
            p.get("network_protocol") or "",
            p.get("transport_protocol") or "",
            p.get("application_protocol") or "",
            p["packet_length"],
            ",".join(p.get("tcp_flags", [])),
            p["parsing_status"],
            p["summary"],
        ])

    csv_data = output.getvalue()
    filename = f"netscope_export_{int(time.time())}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@api_bp.route("/export/report", methods=["GET"])
def export_report():
    """Generates a standalone, print-ready HTML analysis report for the active session."""
    with session_lock:
        if active_session["analytics"].total_packets == 0:
            return jsonify({"error": "No capture session active. Please load or upload a PCAP first."}), 400

        summary = active_session["analytics"].get_summary()
        summary["active_flows"] = active_session["flow_tracker"].get_flow_count()
        protocols = active_session["analytics"].get_protocol_distribution()
        top_talkers = active_session["analytics"].get_top_talkers()
        top_flows = active_session["flow_tracker"].get_top_flows(limit=10)
        alerts = get_detector().get_all_alerts()
        filename = active_session["filename"] or "capture.pcap"
        capture_id = active_session["capture_id"] or "default"

    html_content = generate_html_report(
        summary=summary,
        protocols=protocols,
        top_talkers=top_talkers,
        top_flows=top_flows,
        alerts=alerts,
        filename=filename,
        capture_id=capture_id,
    )

    download = request.args.get("download", "0") == "1"
    disposition = "attachment" if download else "inline"
    report_filename = f"netscope_report_{os.path.splitext(filename)[0]}_{int(time.time())}.html"

    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"{disposition}; filename={report_filename}"},
    )


@api_bp.route("/captures/compare", methods=["POST"])
def compare_capture_files():
    """
    Compares two PCAP files or compares an uploaded PCAP with the currently active session.
    Supported request formats:
      1. 'file_a' and 'file_b' multipart uploads
      2. 'file' multipart upload compared against active session (Capture A)
      3. 'compare_sample': 'true' compares active session against data/sample_traffic.pcap
    """
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "data/uploads")
    os.makedirs(upload_dir, exist_ok=True)

    file_a = request.files.get("file_a") if request.files else None
    file_b = (request.files.get("file_b") or request.files.get("file")) if request.files else None
    json_body = request.get_json(silent=True) or {}
    compare_with_sample = (
        (request.form.get("compare_sample", "").lower() in ("true", "1"))
        or (json_body.get("compare_sample") is True)
        or (str(json_body.get("compare_sample", "")).lower() in ("true", "1"))
    )

    saved_paths = []
    try:
        # Resolve Capture A
        if file_a and file_a.filename:
            fn_a = secure_filename(file_a.filename)
            path_a = os.path.join(upload_dir, f"cmp_a_{uuid.uuid4().hex[:8]}_{fn_a}")
            file_a.save(path_a)
            saved_paths.append(path_a)
            data_a = analyze_standalone_pcap(path_a, capture_id="cmp-a")
            label_a = fn_a
        else:
            # Fall back to active session
            with session_lock:
                if active_session["analytics"].total_packets == 0:
                    return jsonify({"error": "No active capture to compare against. Please upload both files or load an active capture."}), 400
                summary_a = active_session["analytics"].get_summary()
                summary_a["active_flows"] = active_session["flow_tracker"].get_flow_count()
                summary_a["filename"] = active_session["filename"] or "Active Session"
                summary_a["file_size_bytes"] = 0
                data_a = {
                    "summary": summary_a,
                    "protocols": active_session["analytics"].get_protocol_distribution(),
                    "top_talkers": active_session["analytics"].get_top_talkers(),
                    "flows_count": active_session["flow_tracker"].get_flow_count(),
                    "top_flows": active_session["flow_tracker"].get_top_flows(limit=5),
                    "alerts": get_detector().get_all_alerts(),
                }
                label_a = summary_a["filename"]

        # Resolve Capture B
        if file_b and file_b.filename:
            fn_b = secure_filename(file_b.filename)
            path_b = os.path.join(upload_dir, f"cmp_b_{uuid.uuid4().hex[:8]}_{fn_b}")
            file_b.save(path_b)
            saved_paths.append(path_b)
            data_b = analyze_standalone_pcap(path_b, capture_id="cmp-b")
            label_b = fn_b
        elif compare_with_sample:
            sample_path = "data/sample_traffic.pcap"
            if not os.path.exists(sample_path):
                return jsonify({"error": "Sample PCAP fixture not found on server."}), 404
            data_b = analyze_standalone_pcap(sample_path, capture_id="cmp-sample")
            label_b = "sample_traffic.pcap (Baseline)"
        else:
            return jsonify({"error": "Please provide a second PCAP file ('file_b' or 'file') to compare against."}), 400

        # Run comparison
        result = compare_captures(data_a, data_b, label_a=label_a, label_b=label_b)
        return jsonify(result)

    except PcapReaderError as pe:
        return jsonify({"error": f"PCAP parsing failed: {str(pe)}"}), 400
    except Exception as exc:
        return jsonify({"error": f"Comparison failed: {str(exc)}"}), 500
    finally:
        for p in saved_paths:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


# =====================================================================
# FEATURE A: INTERACTIVE NETWORK TOPOLOGY ENDPOINTS
# =====================================================================

@api_bp.route("/topology", methods=["GET"])
def get_topology():
    """Generates an interactive host communication graph from active flows and alerts."""
    min_packets = request.args.get("min_packets", 1, type=int)
    protocol_filter = request.args.get("protocol", "").strip()
    search = request.args.get("search", "").strip()

    with session_lock:
        flows = active_session["flow_tracker"].get_top_flows(limit=1000)
        alerts = get_detector().get_all_alerts()
    topology = build_network_topology(
        flows=flows,
        alerts=alerts,
        min_packets=min_packets,
        protocol_filter=protocol_filter,
        search=search,
    )
    return jsonify(topology)


# =====================================================================
# FEATURE B: SECURITY INCIDENT CENTER ENDPOINTS
# =====================================================================

@api_bp.route("/incidents", methods=["GET"])
def list_incidents():
    """Returns correlated security incidents with status, severity, and host filters."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    host = request.args.get("host")

    with session_lock:
        correlator = active_session.get("incident_correlator")
        mem_incidents = correlator.get_all_incidents(status=status, severity=severity, host=host) if correlator else []

    if not mem_incidents:
        db = get_db()
        db_incidents = db.get_incidents(status=status, severity=severity)
        return jsonify({"incidents": db_incidents})

    return jsonify({"incidents": mem_incidents})


@api_bp.route("/incidents/<incident_id>", methods=["GET"])
def get_incident_detail(incident_id: str):
    """Retrieves detailed forensic evidence and context for a specific incident."""
    with session_lock:
        correlator = active_session.get("incident_correlator")
        inc = correlator.get_incident(incident_id) if correlator else None

    if not inc:
        db = get_db()
        inc = db.get_incident(incident_id)

    if not inc:
        return jsonify({"error": f"Incident {incident_id} not found."}), 404

    return jsonify(inc)


@api_bp.route("/incidents/<incident_id>", methods=["PATCH"])
def update_incident(incident_id: str):
    """Updates investigation status and analyst notes for a security incident."""
    data = request.get_json() or {}
    new_status = data.get("status")
    notes = data.get("analyst_notes")
    if not new_status and notes is None:
        return jsonify({"error": "No status or notes provided for update."}), 400

    updated_inc = None
    with session_lock:
        correlator = active_session.get("incident_correlator")
        if correlator:
            updated_inc = correlator.update_status(incident_id, new_status or "New", notes)

    db = get_db()
    db.update_incident_status(incident_id, new_status or (updated_inc.get("status") if updated_inc else "New"), notes)
    if not updated_inc:
        updated_inc = db.get_incident(incident_id)

    return jsonify({"success": True, "incident": updated_inc})


# =====================================================================
# FEATURE C: TRAFFIC REPLAY & DEMONSTRATION LAB ENDPOINTS
# =====================================================================

@api_bp.route("/replay/scenarios", methods=["GET"])
def get_replay_scenarios():
    """Lists available deterministic demonstration lab scenarios and current state."""
    return jsonify({
        "scenarios": list(SCENARIO_METADATA.values()),
        "current_status": replay_engine.get_status(),
    })


@api_bp.route("/replay/status", methods=["GET"])
def get_replay_status():
    """Polls real-time progress, speed, and rule hits of the demonstration replay engine."""
    return jsonify(replay_engine.get_status())


@api_bp.route("/replay/start", methods=["POST"])
def start_replay():
    """Initializes and runs a deterministic traffic scenario."""
    data = request.get_json() or {}
    scenario_id = data.get("scenario_id", "normal_traffic")
    speed = float(data.get("speed", 2.0))

    if scenario_id not in SCENARIO_METADATA:
        return jsonify({"error": f"Invalid demonstration scenario ID: {scenario_id}"}), 400

    # Reset active session state for demonstration replay
    scenario_info = SCENARIO_METADATA[scenario_id]
    reset_active_session(
        capture_id=f"replay-{scenario_id}-{uuid.uuid4().hex[:6]}",
        filename=f"{scenario_info['name']} (Lab Replay)",
        mode="replay",
    )

    app = current_app._get_current_object()
    def context_aware_callback(record):
        with app.app_context():
            on_packet_received(record)

    status = replay_engine.start(scenario_id, packet_callback=context_aware_callback, speed=speed)
    return jsonify({"success": True, "status": status})


@api_bp.route("/replay/pause", methods=["POST"])
def pause_replay():
    """Temporarily pauses the demonstration replay player."""
    return jsonify({"success": True, "status": replay_engine.pause()})


@api_bp.route("/replay/resume", methods=["POST"])
def resume_replay():
    """Resumes a paused demonstration replay player."""
    return jsonify({"success": True, "status": replay_engine.resume()})


@api_bp.route("/replay/stop", methods=["POST"])
def stop_replay():
    """Halts demonstration replay execution."""
    return jsonify({"success": True, "status": replay_engine.stop()})


@api_bp.route("/replay/reset", methods=["POST"])
def reset_replay():
    """Stops replay and restores the workbench to a clean idle state."""
    replay_engine.reset()
    reset_active_session(capture_id="", filename="", mode="idle")
    return jsonify({"success": True, "status": replay_engine.get_status()})


# =====================================================================
# FEATURE F: INVESTIGATION CASES & REPORTING ENDPOINTS
# =====================================================================

@api_bp.route("/cases", methods=["GET"])
def list_cases():
    """Returns all forensic investigation cases."""
    db = get_db()
    cases = db.get_cases()
    return jsonify({"cases": cases})


@api_bp.route("/cases", methods=["POST"])
def create_case():
    """Creates a new security investigation case."""
    data = request.get_json() or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "Case title is required."}), 400

    case_id = data.get("case_id") or f"CASE-{int(time.time())}"
    summary = data.get("summary", "")
    priority = data.get("priority", "Medium")
    status = data.get("status", "Open")
    analyst = data.get("analyst", "SecOps Analyst")

    db = get_db()
    db.create_case(case_id, title, summary, priority, status, analyst)

    # Attach initial artifacts
    for art in data.get("artifacts", []):
        db.attach_case_artifact(
            case_id,
            art.get("artifact_type", "reference"),
            str(art.get("artifact_id", "")),
            art.get("metadata", {}),
        )

    # Add initial note if present
    if data.get("initial_note"):
        db.add_case_note(case_id, data["initial_note"], author=analyst)

    return jsonify({"success": True, "case": db.get_case(case_id)}), 201


@api_bp.route("/cases/<case_id>", methods=["GET"])
def get_case(case_id: str):
    """Retrieves full investigation case details including notes and forensic artifacts."""
    db = get_db()
    case = db.get_case(case_id)
    if not case:
        return jsonify({"error": f"Case {case_id} not found."}), 404
    return jsonify(case)


@api_bp.route("/cases/<case_id>", methods=["PATCH"])
def update_case(case_id: str):
    """Updates case metadata (title, summary, status, priority, analyst)."""
    data = request.get_json() or {}
    db = get_db()
    updated = db.update_case(case_id, data)
    if not updated:
        return jsonify({"error": f"Case {case_id} not found."}), 404
    return jsonify({"success": True, "case": updated})


@api_bp.route("/cases/<case_id>/notes", methods=["POST"])
def add_case_note(case_id: str):
    """Appends an analyst note/finding to the investigation case."""
    data = request.get_json() or {}
    note = data.get("note", "").strip()
    if not note:
        return jsonify({"error": "Note text is required."}), 400
    author = data.get("author", "SecOps Analyst")

    db = get_db()
    if not db.get_case(case_id):
        return jsonify({"error": f"Case {case_id} not found."}), 404
    created_note = db.add_case_note(case_id, note, author=author)
    return jsonify({"success": True, "note": created_note}), 201


@api_bp.route("/cases/<case_id>/artifacts", methods=["POST"])
def attach_case_artifact(case_id: str):
    """Attaches a forensic artifact (incident, packet, flow, host) to the case."""
    data = request.get_json() or {}
    art_type = data.get("artifact_type", "reference")
    art_id = data.get("artifact_id")
    if not art_id:
        return jsonify({"error": "artifact_id is required."}), 400
    metadata = data.get("metadata", {})

    db = get_db()
    if not db.get_case(case_id):
        return jsonify({"error": f"Case {case_id} not found."}), 404
    attached = db.attach_case_artifact(case_id, art_type, str(art_id), metadata)
    return jsonify({"success": True, "artifact": attached}), 201


@api_bp.route("/cases/<case_id>/report", methods=["GET"])
def export_case_report(case_id: str):
    """Generates and exports a standalone, print-ready HTML case investigation report."""
    db = get_db()
    case = db.get_case(case_id)
    if not case:
        return jsonify({"error": f"Case {case_id} not found."}), 404
    html_report = generate_case_html_report(case)
    download = request.args.get("download", "0") == "1"
    disposition = "attachment" if download else "inline"
    report_filename = f"netscope_case_{case_id}_{int(time.time())}.html"
    return Response(
        html_report,
        mimetype="text/html",
        headers={"Content-Disposition": f"{disposition}; filename={report_filename}"},
    )
