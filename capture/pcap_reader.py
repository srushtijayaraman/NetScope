"""
NetScope Offline PCAP Reader
Safely reads and processes PCAP and PCAPNG files incrementally.
Validates file integrity, enforces size limits, tracks processing performance,
and feeds parsed packets into the analytics engine and memory buffer.
"""

import os
import time
from typing import Callable, Optional
from scapy.utils import PcapReader
from analyzer.parser import parse_packet


class PcapReaderError(Exception):
    """Custom exception for PCAP ingestion failures."""
    pass


class OfflinePcapProcessor:
    def __init__(self, max_packets_memory: int = 10000):
        self.max_packets_memory = max_packets_memory

    def process_file(
        self,
        filepath: str,
        capture_id: str = "default",
        packet_callback: Optional[Callable[[dict], None]] = None,
    ) -> dict:
        """
        Reads a PCAP/PCAPNG file incrementally.
        Calls packet_callback for every parsed packet record.
        Returns processing metadata summary.
        """
        if not os.path.exists(filepath):
            raise PcapReaderError(f"File not found: {filepath}")

        file_size = os.path.getsize(filepath)
        if file_size == 0:
            raise PcapReaderError("File is empty (0 bytes).")

        start_wall_time = time.perf_counter()
        packet_count = 0
        skipped_count = 0
        records_sample = []

        reader = None
        f = None
        base_timestamp = None
        try:
            f = open(filepath, "rb")
            reader = PcapReader(f)
            for pkt in reader:
                packet_count += 1
                try:
                    if base_timestamp is None and getattr(pkt, "time", None) is not None:
                        base_timestamp = float(pkt.time)
                    record = parse_packet(pkt, packet_id=packet_count, capture_id=capture_id, base_timestamp=base_timestamp)
                    if packet_callback:
                        packet_callback(record)
                    if len(records_sample) < self.max_packets_memory:
                        records_sample.append(record)
                except Exception:
                    skipped_count += 1
                    continue
        except PcapReaderError:
            raise
        except Exception as exc:
            if packet_count == 0:
                raise PcapReaderError(f"Failed to parse capture file: {str(exc)}")
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass
            if f and not f.closed:
                try:
                    f.close()
                except Exception:
                    pass

        elapsed_wall_time = time.perf_counter() - start_wall_time

        if packet_count == 0:
            raise PcapReaderError("No valid packets could be extracted from this capture file.")

        return {
            "capture_id": capture_id,
            "filename": os.path.basename(filepath),
            "file_size_bytes": file_size,
            "packets_processed": packet_count,
            "packet_count": packet_count,
            "packets_skipped": skipped_count,
            "processing_time_seconds": round(elapsed_wall_time, 4),
            "processing_pps": round(packet_count / elapsed_wall_time, 2) if elapsed_wall_time > 0 else 0.0,
            "records_in_memory": len(records_sample),
            "records": records_sample,
        }
