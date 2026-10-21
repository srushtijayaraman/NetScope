# NetScope: Automated Test Execution Report

## 1. Test Execution Summary
- **Execution Date**: 2026-10-21
- **Platform**: Windows 11 (NT 10.0.26300.0), Python 3.13.2 (64-bit)
- **Test Framework**: `pytest-9.1.1`, `pluggy-1.7.0`
- **Total Tests Discovered**: 61
- **Tests Passed**: 61 (100.0%)
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Total Execution Time**: 2.50 seconds
- **Warning Count**: 0 (Zero warnings, clean runtime)

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
| TC-API-09 | `test_empty_session_and_error_handling` | **PASSED** | Verifies `POST /api/captures/reset`, clean empty stats, and 400/404 error guards on uninitialized states |

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
| TC-PARSE-04 | `test_parse_icmp_packet` | **PASSED** | Decodes ICMP Echo Request Type 8, ID, Sequence |
| TC-PARSE-05 | `test_parse_ipv6_packet` | **PASSED** | Decodes IPv6 header, hop limits, and 128-bit addresses |
| TC-PARSE-06 | `test_parse_fragment_packet` | **PASSED** | Identifies IP fragment via More Fragments (MF) flag |
| TC-PARSE-07 | `test_parse_http_payload` | **PASSED** | Extracts HTTP method (`GET`), URI, and status line |
| TC-PARSE-08 | `test_parse_tls_handshake_payload`| **PASSED** | Identifies TLS ClientHello handshake record (0x16, 0x0303) |
| TC-PARSE-09 | `test_tcp_flag_decoder` | **PASSED** | Correctly maps flag combinations (SYN+ACK, FIN+ACK, RST, PSH) |
| TC-PARSE-10 | `test_defensive_missing_fields` | **PASSED** | Gracefully decodes packets missing transport or payload layers |
| TC-PARSE-11 | `test_parse_dns_query_and_response_details` | **PASSED** | Extracts transaction ID, QNAME, and answers without deprecation warnings |
| TC-PARSE-12 | `test_parse_corrupt_packet_safe` | **PASSED** | Malformed packet bytes return safe status without throwing exceptions |

### F. Offline PCAP Reading (`tests/test_pcap_reader.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-PCAP-01 | `test_read_valid_sample_pcap` | **PASSED** | Reads 60 packets from `sample_traffic.pcap` with accurate timings |
| TC-PCAP-02 | `test_missing_file_error` | **PASSED** | Raises `PcapReaderError` with friendly message when file not found |
| TC-PCAP-03 | `test_empty_file_error` | **PASSED** | Raises `PcapReaderError` on 0-byte file |
| TC-PCAP-04 | `test_corrupted_file_error` | **PASSED** | Raises `PcapReaderError` on invalid/truncated file header |

### G. Traffic Statistics Engine (`tests/test_statistics.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-STAT-01 | `test_empty_analytics` | **PASSED** | Zero-packet state returns 0 duration, 0 PPS, 0 bps safely |
| TC-STAT-02 | `test_packet_and_byte_counts` | **PASSED** | Verifies arithmetic sum of packet lengths and packet counts |
| TC-STAT-03 | `test_protocol_distribution_percentages` | **PASSED** | Confirms percentages sum to 100.0% per protocol layer |
| TC-STAT-04 | `test_top_talkers_and_ports` | **PASSED** | Aggregates volume by source, destination, and unified host IP |
| TC-STAT-05 | `test_timeline_bucketing` | **PASSED** | Confirms time-series grouping and rate calculations per interval |

### H. TCP Conversation Inspector (`tests/test_conversation_inspector.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-CONV-01 | `test_complete_tcp_handshake_and_teardown` | **PASSED** | Verifies 3-way handshake state (`SYN_SENT` &rarr; `SYN_ACK` &rarr; `ESTABLISHED`), DATA, and FIN closing |
| TC-CONV-02 | `test_retransmission_detection` | **PASSED** | Detects repeated sequence numbers with identical payload lengths, flagging `is_retransmission: True` |
| TC-CONV-03 | `test_midstream_and_incomplete_handshakes` | **PASSED** | Correctly classifies mid-stream traffic as `MID_STREAM` and connection aborts as `RESET` |
| TC-CONV-04 | `test_timeline_api_endpoint` | **PASSED** | Verifies `/api/flows/<flow_id>/timeline` returns chronological event ladder and 404 on missing flows |

### I. Capture Comparison (`tests/test_comparator.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-COMP-01 | `test_compute_metric_diff_zero_guard` | **PASSED** | Prevents division-by-zero crashes when baseline metrics are 0 |
| TC-COMP-02 | `test_standalone_pcap_analysis` | **PASSED** | Parses capture files in an isolated sandbox without mutating active global session state |
| TC-COMP-03 | `test_compare_identical_captures` | **PASSED** | Confirms 0% difference and clean equality across identical capture files |
| TC-COMP-04 | `test_disparate_duration_warning` | **PASSED** | Automatically emits methodological warning banner when observation windows differ significantly |
| TC-COMP-05 | `test_compare_api_endpoint` | **PASSED** | Validates `/api/captures/compare` with sample comparison and input validation |

### J. HTML Report Generation (`tests/test_report_generator.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-REP-01 | `test_html_report_generation_structure` | **PASSED** | Verifies standalone HTML document contains verified KPIs, protocol tables, flows, and alerts |
| TC-REP-02 | `test_html_report_xss_escaping` | **PASSED** | Asserts that hostile filenames and payload injection strings are strictly sanitized via `html.escape` |
| TC-REP-03 | `test_report_api_endpoint` | **PASSED** | Tests `/api/export/report` returns HTTP 200 `text/html` and HTTP 400 guard on empty captures |

### K. Deterministic PCAP Fixtures (`tests/test_pcap_fixtures.py`)
| Test ID | Test Name | Status | Verified Outcome |
|---|---|---|---|
| TC-FIX-01 | `test_fixture_normal_handshake_and_bidirectional_data_teardown` | **PASSED** | Generates physical 10-packet PCAP: validates SYN -> SYN-ACK -> ACK -> Data -> FIN -> ACK lifecycle |
| TC-FIX-02 | `test_fixture_incomplete_handshakes` | **PASSED** | Generates SYN-only and SYN+SYN-ACK PCAPs; verifies exact uncompleted state categorizations |
| TC-FIX-03 | `test_fixture_connection_resets` | **PASSED** | Generates connection refusal (SYN -> RST) and abort PCAPs; confirms state transitions to `RESET` |
| TC-FIX-04 | `test_fixture_bidirectional_reverse_traffic` | **PASSED** | Validates symmetric 5-tuple flow assignment and exact forward vs reverse octet and frame accounting |
| TC-FIX-05 | `test_fixture_retransmission_edge_cases` | **PASSED** | Generates duplicate payload segment PCAP; validates exact sequence retransmission tracking |

---

## 3. Independent Wireshark Verification Status
- **Host Status**: *Wireshark and TShark CLI binaries are not installed in the local environment.*
- **Methodological Standard**: Live automated execution of TShark binary was **not** claimed. Instead, all mathematical formulas (Throughput, PPS, Duration, Flag combinations, 5-tuple hashing) were directly matched against Wireshark's standard RFC specifications (RFC 793, RFC 8200) and verified against Scapy ground truth.
- **External Reproduction**: Complete manual Wireshark and TShark CLI display filter commands are provided in `docs/wireshark_verification.md` for independent replication.

---

## 4. Defects Discovered & Remediations Applied
1. **Windows Temporary File Lock**: `NamedTemporaryFile` in Windows holds a mandatory OS-level file lock, causing `PermissionError: [WinError 32]` when Scapy or the test cleanup attempted to delete the temporary PCAP.
   - *Remediation*: Explicitly called `tf.close()` prior to ingestion, and ensured `PcapReader` file descriptors are cleanly wrapped in `try...finally` blocks.
2. **In-Memory SQLite Multi-Connection Volatility**: Setting `DATABASE_PATH = ":memory:"` created isolated databases per connection, leading to `sqlite3.OperationalError: no such table: sessions`.
   - *Remediation*: Updated `TestConfig` to use a thread-isolated test SQLite file (`netscope_test_<pid>.db`), ensuring table schemas persist reliably across request contexts.
3. **Scapy 2.8 PacketListField DNS Deprecation Warning**: Accessing `.qd` or `.an` directly on DNS packets in Scapy 2.8 emitted deprecation warnings.
   - *Remediation*: Cast `an_layer` cleanly to `list` before iterating records, eliminating all `DeprecationWarning` messages.
4. **Distinction of Heuristic Alerts vs Observable Facts**: Alert titles previously implied definitive security intrusions without stating heuristic bounds.
   - *Remediation*: Prefixed with `Heuristic: ... (Unconfirmed)` or `Observation: ...`, attaching exact time window, threshold, observed value, and supporting packet references.
5. **Alert Card `undefined` Field Bug**: Frontend alert card templates accessed `alt.observed` and `alt.threshold`, whereas backend detector populated `observed_metric` and `configured_threshold`, rendering `Observed: undefined` and `Threshold: undefined`.
   - *Remediation*: Normalized both backend dictionary keys and SQLite schema to provide `observed_value` / `observed_metric` and `threshold` / `configured_threshold`, with defensive frontend fallbacks and regression tests.
6. **Active Flow Count Inconsistency**: The top KPI card displayed total active 5-tuple flows (52), while the flows card fetched top talkers with a hard-coded limit of 8, causing user confusion.
   - *Remediation*: Created dedicated `/api/flows?limit=...` endpoint returning `total_flows` alongside paginated/filtered flows, and labeled the card dynamically: `Showing Top 10 of 52 Flows`.
7. **Single-Theme Limitation & Visual Ergonomics**: Previous dashboard supported dark mode only and suffered from nested scrollbars, unstyled default browser controls, and poor contrast in bright lab lighting.
   - *Remediation*: Implemented NetScope Design System with complete Light and Dark theme tokens, zero-flash startup script, local storage persistence, live Plotly chart relayout without data reloading, and full keyboard accessibility.
8. **Duplicate Endpoint Return Statement**: `get_packets()` contained a redundant second `return jsonify(...)` block.
   - *Remediation*: Cleaned up dead return statement.
9. **Set Serialization Exception in Flow Objects**: Attempting to serialize `flow_obj` directly raised `TypeError: Object of type set is not JSON serializable` due to `_seen_segments`.
   - *Remediation*: Moved `_seen_segments` into an external `self.flow_segments` mapping and sanitized `get_flow_by_id` to exclude private attributes.
10. **Syntax Warning on Python 3.13 Escape Sequences**: HTML report template contained LaTeX-style math backslashes causing `SyntaxWarning: invalid escape sequence`.
    - *Remediation*: Replaced with standard text notation `(t_max - t_min)` and `(total_bytes * 8) / duration`.
11. **Python 3.13 SQLite Unclosed Connection ResourceWarning**: `with self._get_connection() as conn:` in Python's `sqlite3` only managed transaction commit/rollback, not connection closure, causing Python 3.13 to emit 84 `ResourceWarning: unclosed database` warnings during test runs.
    - *Remediation*: Implemented `@contextmanager` in `storage/database.py` that yields `conn` and strictly executes `conn.close()` in a `finally` block.
12. **Incomplete TCP Handshake (SYN + SYN-ACK without final ACK) Status Fallthrough**: When a 2-packet incomplete handshake occurred, the handshake categorization lacked a specific check for `_saw_syn and _saw_syn_ack and not _saw_handshake_ack`, leaving the status unchanged as `"Incomplete (SYN Sent Only)"`.
    - *Remediation*: Added `"Incomplete (SYN-ACK Received, Missing Final ACK)"` categorization in `analyzer/flow_tracker.py` and supported data-bearing final ACKs.
13. **Capture Session Reset REST Endpoint**: Prior versions lacked an explicit HTTP endpoint to reset active sessions, requiring server restart to clear in-memory buffers.
    - *Remediation*: Introduced `POST /api/captures/reset` in `routes/api.py`.
14. **Process File Default Capture ID**: `OfflinePcapProcessor.process_file` required a positional `capture_id` argument without a default value, complicating direct fixture testing.
    - *Remediation*: Added default `capture_id="default"` and added `packet_count` to return dictionary for consistency.
