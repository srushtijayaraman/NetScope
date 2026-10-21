# NetScope: Automated Test Execution Report

## 1. Test Execution Summary
- **Execution Date**: 2026-10-21
- **Platform**: Windows 11 (NT 10.0.26300.0), Python 3.13.2 (64-bit)
- **Test Framework**: `pytest-9.1.1`, `pluggy-1.7.0`
- **Total Tests Discovered**: 34
- **Tests Passed**: 34 (100.0%)
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Total Execution Time**: 0.40 seconds

---

## 2. Granular Results by Test Module

### A. Anomaly Detection (`tests/test_anomaly_detector.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-ALT-01 | `test_syn_flood_rule_triggered` | **PASSED** | Correctly triggers alert upon 5th SYN in window; ignores below threshold |
| TC-ALT-02 | `test_syn_flood_cooldown` | **PASSED** | Suppresses immediate duplicate alerts within 5s cooldown window |
| TC-ALT-03 | `test_port_scan_rule_triggered` | **PASSED** | Detects probing of $\ge 4$ distinct ports by single IP |
| TC-ALT-04 | `test_batch_dominant_host_rule` | **PASSED** | Flags source IP accounting for $>50\%$ of overall traffic volume |

### B. REST API Endpoints (`tests/test_api.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-API-01 | `test_api_health` | **PASSED** | Returns HTTP 200, status "ok", version, and Scapy metadata |
| TC-API-02 | `test_api_interfaces` | **PASSED** | Enumerates network interfaces and accurately reports driver state |
| TC-API-03 | `test_upload_invalid_extension` | **PASSED** | Rejects non-PCAP file (`.exe`) with HTTP 400 Bad Request |
| TC-API-04 | `test_upload_missing_file` | **PASSED** | Returns HTTP 400 when multipart request lacks file payload |
| TC-API-05 | `test_load_sample_and_inspect_metrics`| **PASSED** | Loads 60-packet sample and validates stats, protocols, timeline, alerts, and 404s |

### C. Filtering, Pagination & Export (`tests/test_filters.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-FILT-01 | `test_packet_filtering_workflow` | **PASSED** | Verifies filtering by protocol (ARP/DNS), source IP, search string, and disjoint pagination |
| TC-FILT-02 | `test_csv_export_with_filters` | **PASSED** | Streams valid RFC 4180 CSV containing only filtered records |

### D. Capture Lifecycle & Queue Stress (`tests/test_lifecycle.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-LIFE-01 | `test_live_capture_manager_unsupported_on_current_host` | **PASSED** | Gracefully returns `UNSUPPORTED_BACKEND` when Npcap is missing |
| TC-LIFE-02 | `test_queue_overflow_and_drop_accounting` | **PASSED** | Enqueuing 5 items in a 3-slot queue records 2 drops without blocking |
| TC-LIFE-03 | `test_stop_capture_idempotent` | **PASSED** | Calling stop on an inactive capture returns cleanly without errors |
| TC-LIFE-04 | `test_session_replacement` | **PASSED** | Ingesting a new capture cleanly resets active counters without mixing |

### E. Packet Parsing & Classification (`tests/test_parser.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-PARSE-01 | `test_parse_tcp_syn_packet` | **PASSED** | Extracts IPv4, TCP ports, sequence number 100, SYN flag |
| TC-PARSE-02 | `test_parse_udp_dns_packet` | **PASSED** | Decodes UDP port 53 and extracts DNS query name |
| TC-PARSE-03 | `test_parse_arp_packet` | **PASSED** | Decodes Layer 2 ARP who-has operation, sender/target IPs |
| TC-PARSE-04 | `test_parse_icmp_packet` | **PASSED** | Identifies ICMP Type 8 Echo Request |
| TC-PARSE-05 | `test_parse_ipv6_packet` | **PASSED** | Decodes IPv6 addresses `fe80::1` and `fe80::2` |
| TC-PARSE-06 | `test_parse_fragment_packet` | **PASSED** | Identifies `flags: MF` and records fragment offset |
| TC-PARSE-07 | `test_parse_http_payload` | **PASSED** | Extracts HTTP request line `GET /api/v1/test HTTP/1.1` |
| TC-PARSE-08 | `test_parse_tls_handshake_payload` | **PASSED** | Identifies TLS record byte `0x16 0x03` as TLS |
| TC-PARSE-09 | `test_tcp_flag_decoder` | **PASSED** | Decodes raw bitmask `0x12` into `['SYN', 'ACK']` |
| TC-PARSE-10 | `test_defensive_missing_fields` | **PASSED** | Safely parses raw payloads without IP/port headers |

### F. PCAP Reader (`tests/test_pcap_reader.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-PCAP-01 | `test_read_valid_sample_pcap` | **PASSED** | Ingests 60 packets from `data/sample_traffic.pcap` with 0 skipped |
| TC-PCAP-02 | `test_missing_file_error` | **PASSED** | Raises `PcapReaderError` for non-existent path |
| TC-PCAP-03 | `test_empty_file_error` | **PASSED** | Raises `PcapReaderError` for 0-byte file |
| TC-PCAP-04 | `test_corrupted_file_error` | **PASSED** | Catches corrupted header junk data without application crash |

### G. Mathematical Analytics (`tests/test_statistics.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-STAT-01 | `test_empty_analytics` | **PASSED** | Zero-division guard: returns 0.0 for duration, PPS, throughput, avg size |
| TC-STAT-02 | `test_packet_and_byte_counts` | **PASSED** | Correctly computes total bytes, average size (200.0), PPS (1.0), and throughput (1.6 kbps) |
| TC-STAT-03 | `test_protocol_distribution_percentages` | **PASSED** | Protocol shares sum exactly to 100% (70% TCP, 30% UDP) |
| TC-STAT-04 | `test_top_talkers_and_ports` | **PASSED** | Correctly ranks talkers by volume and packet count |
| TC-STAT-05 | `test_timeline_bucketing` | **PASSED** | Aggregates packets into 1-second chronological buckets |

---

## 3. Defects Discovered & Remediations Applied
During development, the test suite revealed two defects that were immediately rectified:
1. **Windows Temporary File Lock**: `NamedTemporaryFile` in Windows holds a mandatory OS-level file lock, causing `PermissionError: [WinError 32]` when Scapy or the test cleanup attempted to delete the temporary PCAP.
   - *Remediation*: Explicitly called `tf.close()` prior to ingestion, and ensured `PcapReader` file descriptors are cleanly wrapped in `try...finally` blocks.
2. **In-Memory SQLite Multi-Connection Volatility**: Setting `DATABASE_PATH = ":memory:"` created isolated databases per connection, leading to `sqlite3.OperationalError: no such table: sessions`.
   - *Remediation*: Updated `TestConfig` to use a thread-isolated test SQLite file (`netscope_test_<pid>.db`), ensuring table schemas persist reliably across request contexts.
