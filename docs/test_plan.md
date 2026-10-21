# NetScope: Test Plan & Quality Assurance Strategy

## 1. Testing Philosophy
The verification strategy for NetScope is built on deterministic fixtures and academic defensibility:
- No reliance on unpredictable external network traffic for automated tests.
- 100% repeatable synthetic packet captures covering all target protocol headers and edge cases.
- Direct mathematical validation of every metric formula against hand-calculated ground truths.
- Strict isolation of capture lifecycle and queue error handling.

## 2. Test Suite Structure

| Suite File | Category | Scope |
|---|---|---|
| `tests/test_parser.py` | Parser & Classification | Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, fragments, malformed frames |
| `tests/test_statistics.py` | Mathematical Integrity | Packet/byte counts, average size, duration, PPS, throughput (bps/kbps), protocol shares, bucketing |
| `tests/test_pcap_reader.py` | File Ingestion | Valid PCAP reading, missing files, 0-byte files, corrupted header handling |
| `tests/test_anomaly_detector.py` | Security Intelligence | SYN flood heuristic, port scan heuristic, cooldown enforcement, rate spike detection |
| `tests/test_filters.py` | Filtering & Querying | Protocol filters, IP filters, search query, pagination boundaries, CSV export formatting |
| `tests/test_api.py` | API Contract | Health endpoint, interfaces check, PCAP upload, sample loading, stats, 404/400 errors |
| `tests/test_lifecycle.py` | Lifecycle & Queue | Start/stop idempotency, queue overflow drop accounting, session replacement without mixing |

## 3. Test Execution Command
To execute the complete automated test suite:
```bash
pytest -v
```
