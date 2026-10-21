# NetScope: Protocol & Message Format Design

## 1. Normalized Packet Representation Format
Every captured packet is decoded into a standardized JSON-compatible schema to ensure consistent presentation across the API and user interface.

```json
{
  "packet_id": 1,
  "capture_id": "sample-9b7f7c",
  "timestamp": 1700000000.1,
  "timestamp_iso": "2023-11-14 22:13:20.100",
  "packet_length": 74,
  "captured_length": 74,
  "source_mac": "00:11:22:33:44:55",
  "destination_mac": "00:aa:bb:cc:dd:ee",
  "source_ip": "192.168.1.10",
  "destination_ip": "93.184.216.34",
  "network_protocol": "IPv4",
  "transport_protocol": "TCP",
  "source_port": 49152,
  "destination_port": 80,
  "application_protocol": "HTTP",
  "tcp_flags": ["SYN"],
  "tcp_flags_hex": "0x2",
  "tcp_seq": 1000,
  "tcp_ack": 0,
  "summary": "192.168.1.10:49152 -> 93.184.216.34:80 [SYN] Seq=1000 Ack=0",
  "parsing_status": "Parsed",
  "details": {
    "link_layer": {
      "type": "Ethernet",
      "source_mac": "00:11:22:33:44:55",
      "destination_mac": "00:aa:bb:cc:dd:ee",
      "ether_type": "0x800"
    },
    "network_layer": {
      "protocol": "IPv4",
      "source_ip": "192.168.1.10",
      "destination_ip": "93.184.216.34",
      "ttl": 64,
      "identification": 1,
      "fragment_offset": 0,
      "flags": "DF"
    },
    "transport_layer": {
      "protocol": "TCP",
      "source_port": 49152,
      "destination_port": 80,
      "sequence_number": 1000,
      "acknowledgment_number": 0,
      "flags": ["SYN"],
      "flags_hex": "0x2",
      "window_size": 8192,
      "checksum": "0x1a2b"
    },
    "application_layer": {
      "protocol": "HTTP",
      "request_line": "GET /index.html HTTP/1.1"
    }
  }
}
```

---

## 2. Protocol Classification Rules
NetScope adheres to strict, academically grounded classification rules:
1. **Never Infer Protocol From Port Alone**: Port 80 does not guarantee HTTP; port 443 does not guarantee TLS. NetScope inspects payload headers (e.g., verifying `HTTP/1.`, standard request verbs, or TLS record byte `0x16 0x03`).
2. **Defensive Attribute Access**: Every Scapy layer lookup uses `haslayer()` and defensive `getattr()` checks with default fallbacks.
3. **Layer Separation**:
   - Link Layer: Ethernet II (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP).
   - Network Layer: IPv4, IPv6, ARP.
   - Transport Layer: TCP, UDP, ICMP, ICMPv6.
   - Application Layer: DNS, HTTP, TLS, DHCP, NTP, SSH.
4. **Fragmentation Accounting**: IPv4 frames with `flags.MF` (More Fragments) or `frag > 0` are explicitly classified with `parsing_status: "Fragment"` and fragment offsets.
5. **Security Isolation**: Raw packet payloads are never exposed verbatim in the UI or written to disk, preventing accidental disclosure of sensitive credentials.

---

## 3. REST API Contract & Schema

| Endpoint | Method | Parameters | Response Summary |
|---|---|---|---|
| `/api/health` | `GET` | None | Service status, versions, live capture capability |
| `/api/interfaces` | `GET` | None | Available network interfaces, driver diagnostic notes |
| `/api/captures/upload` | `POST` | `multipart/form-data` with `file` | Ingestion status, processing time, summary metrics |
| `/api/captures/load-sample` | `POST` | None | Instant loading of bundled test capture |
| `/api/captures/start` | `POST` | `{"interface": "eth0"}` | Initiates live capture thread pair |
| `/api/captures/stop` | `POST` | None | Stops live capture and commits summary |
| `/api/captures/status` | `GET` | None | Active mode, capture ID, packet count, drop counters |
| `/api/stats` | `GET` | None | Total packets, total bytes, duration, PPS, throughput |
| `/api/protocols` | `GET` | None | Transport, Network, and Application distribution percentages |
| `/api/traffic-timeline` | `GET` | None | Chronological time buckets with PPS and Throughput (Kbps) |
| `/api/top-talkers` | `GET` | `limit`, `sort_by` (`bytes` / `packets`) | Source/Destination IP rankings, top ports, active flows |
| `/api/packets` | `GET` | `page`, `limit`, `search`, `protocol`, `src_ip`, `dst_ip`, `sort_by` | Paginated packet collection with server-side filters |
| `/api/packets/<id>` | `GET` | `id` (int) | Complete multi-layer decoded packet details |
| `/api/alerts` | `GET` | None | Triggered security and rate anomaly alerts |
| `/api/export/csv` | `GET` | Active filter parameters | Downloadable RFC 4180 CSV export stream |
