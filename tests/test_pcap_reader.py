"""
NetScope Offline PCAP Reader Unit Tests
Validates reading real PCAP files, error handling for missing/empty/corrupted files,
and streaming performance callbacks.
"""

import os
import tempfile
import pytest
from capture.pcap_reader import OfflinePcapProcessor, PcapReaderError


def test_read_valid_sample_pcap(sample_pcap_path):
    assert os.path.exists(sample_pcap_path), "sample_traffic.pcap must exist."
    processor = OfflinePcapProcessor(max_packets_memory=100)
    
    collected_records = []
    summary = processor.process_file(
        sample_pcap_path,
        capture_id="test-pcap-1",
        packet_callback=lambda r: collected_records.append(r),
    )

    assert summary["packets_processed"] == 60
    assert summary["packets_skipped"] == 0
    assert len(collected_records) == 60
    assert summary["processing_time_seconds"] > 0.0
    assert summary["processing_pps"] > 0.0
    assert summary["records_in_memory"] == 60


def test_missing_file_error():
    processor = OfflinePcapProcessor()
    with pytest.raises(PcapReaderError) as exc_info:
        processor.process_file("non_existent_file.pcap", capture_id="err-1")
    assert "not found" in str(exc_info.value).lower()


def test_empty_file_error():
    tf = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tf_path = tf.name
    tf.close()

    try:
        processor = OfflinePcapProcessor()
        with pytest.raises(PcapReaderError) as exc_info:
            processor.process_file(tf_path, capture_id="err-empty")
        assert "empty" in str(exc_info.value).lower()
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


def test_corrupted_file_error():
    tf = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tf.write(b"NOT_A_REAL_PCAP_HEADER_JUNK_DATA_1234567890")
    tf_path = tf.name
    tf.close()

    try:
        processor = OfflinePcapProcessor()
        with pytest.raises(PcapReaderError) as exc_info:
            processor.process_file(tf_path, capture_id="err-corrupted")
        assert "failed" in str(exc_info.value).lower() or "no valid packets" in str(exc_info.value).lower()
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)
