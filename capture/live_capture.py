"""
NetScope Live Packet Capture Engine
Manages interface enumeration, capture thread lifecycle, bounded queue buffering,
queue overflow accounting, and graceful shutdown.
"""

import sys
import threading
import queue
import time
from typing import Callable, Optional
import scapy
from scapy.all import conf, sniff
from analyzer.parser import parse_packet


def check_live_capture_capability() -> dict:
    """
    Diagnoses whether the current operating system environment supports live packet capture.
    On Windows, checks for Npcap/WinPcap.
    """
    is_windows = sys.platform.startswith("win")
    if is_windows:
        # Check Scapy's pcap provider
        has_pcap = getattr(conf, "use_pcap", False)
        # Check if conf.manufdb / ifaces are populated
        if not has_pcap:
            return {
                "supported": False,
                "reason": "Npcap/WinPcap driver is not installed on this Windows host.",
                "solution": "Download and install Npcap with 'WinPcap API-compatible mode' enabled from https://npcap.com.",
            }

    try:
        ifaces = conf.ifaces
        if not ifaces:
            return {
                "supported": False,
                "reason": "No network capture interfaces detected by Scapy.",
                "solution": "Verify network adapter status and permissions.",
            }
        return {"supported": True, "reason": "Capture driver detected and operational.", "solution": None}
    except Exception as exc:
        return {
            "supported": False,
            "reason": f"Interface enumeration error: {str(exc)}",
            "solution": "Run with appropriate network permissions or check capture driver.",
        }


def get_available_interfaces() -> list[dict]:
    """Returns a list of network interfaces with identifiers and names."""
    results = []
    try:
        # Iterate over scapy conf.ifaces
        for iface_key, iface_obj in conf.ifaces.items():
            name = getattr(iface_obj, "name", str(iface_key))
            description = getattr(iface_obj, "description", name)
            ip = getattr(iface_obj, "ip", None) or "None"
            mac = getattr(iface_obj, "mac", None) or "None"
            results.append({
                "id": str(iface_key),
                "name": name,
                "description": description,
                "ip": ip,
                "mac": mac,
            })
    except Exception:
        pass

    # Fallback to simple list if dict iteration fails
    if not results:
        try:
            for iface in scapy.arch.get_if_list():
                results.append({"id": str(iface), "name": str(iface), "description": str(iface), "ip": "Unknown", "mac": "Unknown"})
        except Exception:
            pass

    return results


class LiveCaptureManager:
    def __init__(self, queue_size: int = 5000):
        self.queue_size = queue_size
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.status = "STOPPED"  # STOPPED, RUNNING, ERROR, UNSUPPORTED_BACKEND
        self.selected_interface = None
        self.capture_id = None
        self.error_message = None
        
        self.packets_captured = 0
        self.packets_processed = 0
        self.queue_drops = 0
        
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._worker_thread = None
        self._callback = None

    def get_status(self) -> dict:
        return {
            "status": self.status,
            "interface": self.selected_interface,
            "capture_id": self.capture_id,
            "packets_captured": self.packets_captured,
            "packets_processed": self.packets_processed,
            "queue_drops": self.queue_drops,
            "queue_current_size": self.packet_queue.qsize(),
            "error_message": self.error_message,
        }

    def start_capture(
        self,
        interface: Optional[str] = None,
        capture_id: str = "live",
        packet_callback: Optional[Callable[[dict], None]] = None,
    ):
        """Starts live packet capture on a background thread."""
        if self.status == "RUNNING":
            return {"success": False, "error": "Capture is already active."}

        cap_check = check_live_capture_capability()
        if not cap_check["supported"]:
            self.status = "UNSUPPORTED_BACKEND"
            self.error_message = f"{cap_check['reason']} {cap_check.get('solution') or ''}"
            return {"success": False, "error": self.error_message}

        self.status = "RUNNING"
        self.selected_interface = interface
        self.capture_id = capture_id
        self.error_message = None
        self.packets_captured = 0
        self.packets_processed = 0
        self.queue_drops = 0
        self._callback = packet_callback
        self._stop_event.clear()

        # Clear any residual queue items
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

        # Start worker consumer thread
        self._worker_thread = threading.Thread(target=self._process_queue_worker, daemon=True)
        self._worker_thread.start()

        # Start capture thread
        self._capture_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self._capture_thread.start()

        return {"success": True, "message": f"Capture started on interface {interface or 'default'}"}

    def _enqueue_packet(self, pkt):
        self.packets_captured += 1
        try:
            self.packet_queue.put_nowait(pkt)
        except queue.Full:
            self.queue_drops += 1

    def _sniff_worker(self):
        try:
            kwargs = {
                "prn": self._enqueue_packet,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "store": False,
            }
            if self.selected_interface:
                kwargs["iface"] = self.selected_interface

            sniff(**kwargs)
        except Exception as exc:
            self.status = "ERROR"
            self.error_message = f"Live capture halted: {str(exc)}"
        finally:
            if self.status == "RUNNING":
                self.status = "STOPPED"

    def _process_queue_worker(self):
        while not self._stop_event.is_set() or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            self.packets_processed += 1
            try:
                record = parse_packet(pkt, packet_id=self.packets_processed, capture_id=self.capture_id)
                if self._callback:
                    self._callback(record)
            except Exception:
                pass
            finally:
                self.packet_queue.task_done()

    def stop_capture(self) -> dict:
        """Stops live capture cleanly and joins threads with timeout."""
        if self.status != "RUNNING":
            return {"success": True, "message": "Capture was not running."}

        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

        self.status = "STOPPED"
        return {
            "success": True,
            "packets_captured": self.packets_captured,
            "packets_processed": self.packets_processed,
            "queue_drops": self.queue_drops,
        }
