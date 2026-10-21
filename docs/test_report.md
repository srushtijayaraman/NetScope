# NetScope: Automated Test Execution Report

## 1. Test Execution Summary
- **Execution Date**: 2026-10-21
- **Platform**: Windows 11 (NT 10.0.26300.0), Python 3.13.2 (64-bit)
- **Test Framework**: `pytest-9.1.1`, `pluggy-1.7.0`
- **Total Tests Discovered**: 43
- **Tests Passed**: 43 (100.0%)
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Total Execution Time**: 2.21 seconds

---

## 2. Granular Results by Test Module

### A. Anomaly Detection (`tests/test_anomaly_detector.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-ALT-01 | `test_normal_benign_traffic_no_alerts` | **PASSED** | Normal 3-way handshakes and single-port HTTP GET/200 OK generate zero false-positive alerts |
| TC-ALT-02 | `test_false_positive_single_port_repeated_requests` | **PASSED** | Rapid consecutive requests to a single web port (port 80) do NOT trigger port scan alerts |
| TC-ALT-03 | `test_syn_flood_rule_with_packet_references` | **PASSED** | Triggers alert on 5th standalone SYN with complete supporting packet reference list `[1, 2, 3, 4, 5]` |
| TC-ALT-04 | `test_syn_flood_cooldown` | **PASSED** | Suppresses immediate duplicate alerts within cooldown window |
| TC-ALT-05 | `test_port_scan_rule_triggered_with_references` | **PASSED** | Flags probing of $\ge 4$ distinct ports with packet ID references |
| TC-ALT-06 | `test_dynamic_threshold_reconfiguration` | **PASSED** | Dynamically modifies thresholds at runtime; verifies new threshold enforcement |
| TC-ALT-07 | `test_batch_dominant_host_rule` | **PASSED** | Flags source IP accounting for $>50\%$ of overall traffic volume as observable fact |

### B. REST API Endpoints (`tests/test_api.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-API-01 | `test_api_health` | **PASSED** | Returns HTTP 200, status "ok", version, and Scapy metadata |
| TC-API-02 | `test_api_interfaces` | **PASSED** | Enumerates network interfaces and accurately reports driver state |
| TC-API-03 | `test_upload_invalid_extension` | **PASSED** | Rejects non-PCAP file (`.exe`) with HTTP 400 Bad Request |
| TC-API-04 | `test_upload_missing_file` | **PASSED** | Returns HTTP 400 when multipart request lacks file payload |
| TC-API-05 | `test_load_sample_and_inspect_metrics`| **PASSED** | Loads 60-packet sample and validates stats, protocols, timeline, alerts, flows, and 404s |
| TC-API-06 | `test_alerts_config_api` | **PASSED** | Verifies `GET /api/alerts/config`, `POST /api/alerts/config`, and rejection of malformed JSON with HTTP 400 |
| TC-API-07 | `test_alert_fields_integrity_and_no_undefined` | **PASSED** | Verifies all alerts contain valid strings for `observed_value` and `threshold`, eliminating `undefined` |
| TC-API-08 | `test_flows_api_matches_stats_flow_count` | **PASSED** | Verifies `/api/flows` returns `total_flows` matching `/api/stats` `active_flows` and valid schema |

### C. Filtering, Flow Tracking & Export (`tests/test_filters.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-FILT-01 | `test_packet_filtering_workflow` | **PASSED** | Verifies filtering by protocol (ARP/DNS), source IP, search string, and disjoint pagination |
| TC-FILT-02 | `test_csv_export_with_filters` | **PASSED** | Streams valid RFC 4180 CSV containing Flow ID, Relative Time, and filtered records |
| TC-FILT-03 | `test_filters_by_ports_packet_id_and_flow` | **PASSED** | Verifies exact query filtering by `packet_id`, `dst_port`, `flow_id`, and flow detail lookup |

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
| TC-PARSE-11 | `test_parse_dns_query_and_response_details` | **PASSED** | Extracts DNS transaction ID, query type names, response codes, and decoded answer records |
| TC-PARSE-12 | `test_parse_corrupt_packet_safe` | **PASSED** | Gracefully handles non-packet corrupted inputs without crashing, returning `Malformed` |

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
1. **Windows Temporary File Lock**: `NamedTemporaryFile` in Windows holds a mandatory OS-level file lock, causing `PermissionError: [WinError 32]` when Scapy or the test cleanup attempted to delete the temporary PCAP.
   - *Remediation*: Explicitly called `tf.close()` prior to ingestion, and ensured `PcapReader` file descriptors are cleanly wrapped in `try...finally` blocks.
2. **In-Memory SQLite Multi-Connection Volatility**: Setting `DATABASE_PATH = ":memory:"` created isolated databases per connection, leading to `sqlite3.OperationalError: no such table: sessions`.
   - *Remediation*: Updated `TestConfig` to use a thread-isolated test SQLite file (`netscope_test_<pid>.db`), ensuring table schemas persist reliably across request contexts.
3. **Scapy 2.8 PacketListField DNS Deprecation Warning**: Accessing `.qd` or `.an` on DNS packets in Scapy 2.8 emitted deprecation warnings.
   - *Remediation*: Utilized payload chaining and indexed access with upstream warning filtering in `pytest.ini`.
4. **Distinction of Heuristic Alerts vs Observable Facts**: Alert titles previously implied definitive security intrusions without stating heuristic bounds.
   - *Remediation*: Prefixed with `Heuristic: ... (Unconfirmed)` or `Observation: ...`, attaching exact time window, threshold, observed value, and supporting packet references.
5. **Alert Card `undefined` Field Bug**: Frontend alert card templates accessed `alt.observed` and `alt.threshold`, whereas backend detector populated `observed_metric` and `configured_threshold`, rendering `Observed: undefined` and `Threshold: undefined`.
   - *Remediation*: Normalized both backend dictionary keys and SQLite schema to provide `observed_value` / `observed_metric` and `threshold` / `configured_threshold`, with defensive frontend fallbacks and regression tests.
6. **Active Flow Count Inconsistency**: The top KPI card displayed total active 5-tuple flows (52), while the flows card fetched top talkers with a hard-coded limit of 8, causing user confusion.
   - *Remediation*: Created dedicated `/api/flows?limit=...` endpoint returning `total_flows` alongside paginated/filtered flows, and labeled the card dynamically: `Showing Top 10 of 52 Flows`.
7. **Single-Theme Limitation & Visual Ergonomics**: Previous dashboard supported dark mode only and suffered from nested scrollbars, unstyled default browser controls, and poor contrast in bright lab lighting.
   - *Remediation*: Implemented NetScope 2.0 Design System with complete Light and Dark theme tokens, zero-flash startup script, local storage persistence, live Plotly chart relayout without data reloading, and full keyboard accessibility.
