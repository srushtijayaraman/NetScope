"""
NetScope Automated Performance and Verification Benchmarks
Executes reproducible measurements for Experiments A, B, C, D, and E.
Outputs structured JSON and Markdown summary for academic performance documentation.
"""

import os
import sys
import time
import json
import psutil
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

from capture.pcap_reader import OfflinePcapProcessor
from analytics.statistics import TrafficAnalytics
from analyzer.parser import parse_packet
from capture.live_capture import check_live_capture_capability
from app import create_app
from config import TestConfig


def run_benchmarks():
    print("=" * 70)
    print("NETSCOPE PERFORMANCE & VERIFICATION EXPERIMENT SUITE")
    print("=" * 70)
    
    results = {}
    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 * 1024)

    # -------------------------------------------------------------
    # EXPERIMENT A: Offline Processing Throughput
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT A: Offline Processing Throughput ---")
    os.makedirs("data/benchmark_pcaps", exist_ok=True)
    
    # 1. Dataset 1: Small (60 packets)
    ds1_path = "data/sample_traffic.pcap"
    
    # 2. Dataset 2: Medium (500 packets)
    ds2_path = "data/benchmark_pcaps/medium_500.pcap"
    packets_med = []
    base_t = 1700000000.0
    for i in range(500):
        p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=f"10.0.0.{i % 50 + 1}", dst="192.168.1.1") / TCP(sport=10000 + i, dport=80, flags="PA") / Raw(b"x" * (64 + (i % 256)))
        p.time = base_t + (i * 0.01)
        packets_med.append(p)
    wrpcap(ds2_path, packets_med)

    # 3. Dataset 3: Large (2,500 packets)
    ds3_path = "data/benchmark_pcaps/large_2500.pcap"
    packets_large = []
    for i in range(2500):
        proto = TCP if i % 2 == 0 else UDP
        p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=f"192.168.1.{i % 100 + 1}", dst="10.0.0.1") / proto(sport=20000 + (i % 1000), dport=443 if i % 2 == 0 else 53) / Raw(b"netscopedata" * ((i % 8) + 1))
        p.time = base_t + (i * 0.005)
        packets_large.append(p)
    wrpcap(ds3_path, packets_large)

    exp_a_runs = []
    for name, pcap_file in [("Small Capture (Sample)", ds1_path), ("Medium Capture (Synthetic)", ds2_path), ("Large Capture (Synthetic)", ds3_path)]:
        file_size_bytes = os.path.getsize(pcap_file)
        processor = OfflinePcapProcessor(max_packets_memory=5000)
        analytics = TrafficAnalytics()
        
        t0 = time.perf_counter()
        summary = processor.process_file(pcap_file, capture_id=f"bench-{name}", packet_callback=analytics.ingest_packet)
        elapsed = time.perf_counter() - t0
        
        pps = summary["packets_processed"] / elapsed if elapsed > 0 else 0
        mem_after = proc.memory_info().rss / (1024 * 1024)
        
        record = {
            "workload": name,
            "packets": summary["packets_processed"],
            "file_size_kb": round(file_size_bytes / 1024.0, 2),
            "duration_sec": round(elapsed, 4),
            "processing_pps": round(pps, 2),
            "memory_rss_mb": round(mem_after, 2),
            "errors": summary["packets_skipped"],
        }
        exp_a_runs.append(record)
        print(f"[{name}] {record['packets']} pkts | {record['file_size_kb']} KB | {record['duration_sec']}s | {record['processing_pps']} pps | Mem: {record['memory_rss_mb']} MB")

    results["experiment_a"] = exp_a_runs

    # -------------------------------------------------------------
    # EXPERIMENT B: Statistics Mathematical Correctness
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT B: Statistics Mathematical Correctness ---")
    # Ground truth fixture: 4 packets with known lengths and timestamps
    # P1: len 100, t=10.0, TCP
    # P2: len 200, t=11.0, TCP
    # P3: len 300, t=12.0, UDP
    # P4: len 400, t=14.0, ICMP
    # Total pkts = 4
    # Total bytes = 1000
    # Avg size = 250.0
    # Duration = 14.0 - 10.0 = 4.0s
    # Capture PPS = 4 / 4.0 = 1.0 pps
    # Throughput = (1000 * 8) / 4.0 = 2000.0 bps = 2.0 kbps
    # TCP share = 2/4 = 50.0%, UDP = 1/4 = 25.0%, ICMP = 1/4 = 25.0%
    b_analytics = TrafficAnalytics()
    fixtures = [
        {"packet_length": 100, "timestamp": 10.0, "network_protocol": "IPv4", "transport_protocol": "TCP"},
        {"packet_length": 200, "timestamp": 11.0, "network_protocol": "IPv4", "transport_protocol": "TCP"},
        {"packet_length": 300, "timestamp": 12.0, "network_protocol": "IPv4", "transport_protocol": "UDP"},
        {"packet_length": 400, "timestamp": 14.0, "network_protocol": "IPv4", "transport_protocol": "ICMP"},
    ]
    for p in fixtures:
        b_analytics.ingest_packet(p)

    computed_summary = b_analytics.get_summary()
    computed_dist = b_analytics.get_protocol_distribution()
    computed_tp = b_analytics.get_throughput()

    checks = [
        ("Total Packets", 4, computed_summary["total_packets"]),
        ("Total Bytes", 1000, computed_summary["total_bytes"]),
        ("Average Packet Size (Bytes)", 250.0, computed_summary["average_packet_size_bytes"]),
        ("Capture Duration (Seconds)", 4.0, computed_summary["capture_duration_seconds"]),
        ("Capture Rate (PPS)", 1.0, computed_summary["capture_pps"]),
        ("Throughput (bps)", 2000.0, computed_tp["bps"]),
        ("Throughput (kbps)", 2.0, computed_tp["kbps"]),
        ("TCP Protocol Share (%)", 50.0, computed_dist["transport"]["TCP"]["percentage"]),
        ("UDP Protocol Share (%)", 25.0, computed_dist["transport"]["UDP"]["percentage"]),
        ("ICMP Protocol Share (%)", 25.0, computed_dist["transport"]["ICMP"]["percentage"]),
    ]

    exp_b_results = []
    all_b_passed = True
    for metric_name, expected, actual in checks:
        matched = (expected == actual)
        if not matched:
            all_b_passed = False
        exp_b_results.append({
            "metric": metric_name,
            "expected": expected,
            "actual": actual,
            "verified": matched,
        })
        print(f"[{'PASS' if matched else 'FAIL'}] {metric_name}: Expected {expected}, Got {actual}")

    results["experiment_b"] = exp_b_results

    # -------------------------------------------------------------
    # EXPERIMENT C: Filter Query Latency
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT C: Filter Query Response Latency ---")
    app = create_app(TestConfig)
    client = app.test_client()
    # Ingest medium dataset (500 packets)
    client.post("/api/captures/load-sample")

    filters_to_test = [
        ("No Filter (All 60 pkts)", "/api/packets?limit=50"),
        ("Protocol Filter (TCP)", "/api/packets?protocol=TCP&limit=50"),
        ("Protocol Filter (ARP)", "/api/packets?protocol=ARP&limit=50"),
        ("Source IP Filter (10.0.0.99)", "/api/packets?src_ip=10.0.0.99&limit=50"),
        ("Search String (who-has)", "/api/packets?search=who-has&limit=50"),
        ("Combined Filter (TCP + 10.0.0.88)", "/api/packets?protocol=TCP&src_ip=10.0.0.88&limit=50"),
    ]

    exp_c_results = []
    for label, url in filters_to_test:
        latencies = []
        for _ in range(25):
            t0 = time.perf_counter()
            r = client.get(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)
        avg_ms = sum(latencies) / len(latencies)
        min_ms = min(latencies)
        max_ms = max(latencies)
        record = {
            "query_type": label,
            "endpoint": url,
            "avg_latency_ms": round(avg_ms, 3),
            "min_latency_ms": round(min_ms, 3),
            "max_latency_ms": round(max_ms, 3),
        }
        exp_c_results.append(record)
        print(f"[{label}] Avg: {record['avg_latency_ms']} ms (Min: {record['min_latency_ms']} ms, Max: {record['max_latency_ms']} ms)")

    results["experiment_c"] = exp_c_results

    # -------------------------------------------------------------
    # EXPERIMENT D: Dashboard API Latency
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT D: Dashboard API Endpoints Latency ---")
    endpoints = [
        ("Health Check", "/api/health"),
        ("Summary Statistics", "/api/stats"),
        ("Protocol Breakdown", "/api/protocols"),
        ("Traffic Timeline", "/api/traffic-timeline"),
        ("Top Talkers & Flows", "/api/top-talkers"),
        ("Active Flows", "/api/flows"),
        ("Security Alerts", "/api/alerts"),
        ("Alert Config", "/api/alerts/config"),
        ("CSV Export", "/api/export/csv"),
    ]

    exp_d_results = []
    for label, ep in endpoints:
        latencies = []
        for _ in range(20):
            t0 = time.perf_counter()
            r = client.get(ep)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        avg_ms = sum(latencies) / len(latencies)
        record = {
            "endpoint_name": label,
            "path": ep,
            "avg_ms": round(avg_ms, 3),
            "min_ms": round(min(latencies), 3),
            "max_ms": round(max(latencies), 3),
        }
        exp_d_results.append(record)
        print(f"[{label}] {ep} -> {record['avg_ms']} ms")

    results["experiment_d"] = exp_d_results

    # -------------------------------------------------------------
    # EXPERIMENT E: Live Capture Constraints
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT E: Live Capture Environment Assessment ---")
    cap_info = check_live_capture_capability()
    results["experiment_e"] = {
        "os_platform": sys.platform,
        "supported": cap_info["supported"],
        "reason": cap_info["reason"],
        "solution": cap_info.get("solution"),
    }
    print(f"Live Capture Supported: {cap_info['supported']}")
    print(f"Reason: {cap_info['reason']}")
    if cap_info.get("solution"):
        print(f"Remediation: {cap_info['solution']}")

    # Save results to json
    os.makedirs("docs", exist_ok=True)
    with open("docs/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nBenchmark results successfully exported to docs/benchmark_results.json")


if __name__ == "__main__":
    run_benchmarks()
