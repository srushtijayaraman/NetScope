# NetScope: Wireshark Packet-Level Verification Procedure

## 1. Independent Verification Status
- **Host Verification Status**: *Outstanding on current host (Wireshark / TShark binaries are not installed in the current environment).*
- **Reproducibility**: Complete step-by-step TShark and Wireshark verification commands are detailed below for external reproduction and academic viva examination.

---

## 2. Verification Methodology
To verify that NetScope's parser, decoders, and metrics conform to industry-standard implementations, compare NetScope's output against Wireshark on the bundled reference capture: `data/sample_traffic.pcap` (60 packets).

---

## 3. Protocol-by-Protocol Comparison Matrix

| Packet ID | Protocol | NetScope Decoded Value | Wireshark Display Filter & Expected Value | Match Status |
|---|---|---|---|---|
| **#1** | ARP (Who-has) | `psrc: 192.168.1.10`, `pdst: 192.168.1.1`, Op: 1 | `arp.opcode == 1` & `arp.src.proto_ipv4 == 192.168.1.10` | Expected Identical |
| **#2** | ARP (Is-at) | `psrc: 192.168.1.1`, `pdst: 192.168.1.10`, Op: 2 | `arp.opcode == 2` & `arp.dst.proto_ipv4 == 192.168.1.10` | Expected Identical |
| **#3** | DNS Query | `example.com`, UDP sport: 53210, dport: 53 | `dns.flags.response == 0` & `dns.qry.name == "example.com"` | Expected Identical |
| **#4** | DNS Response | `93.184.216.34`, UDP sport: 53, dport: 53210 | `dns.flags.response == 1` & `dns.a == 93.184.216.34` | Expected Identical |
| **#5** | TCP SYN | `192.168.1.10:49152 -> 93.184.216.34:80`, Flags: `[SYN]`, Seq: 1000 | `tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.seq == 1000` | Expected Identical |
| **#6** | TCP SYN-ACK | `93.184.216.34:80 -> 192.168.1.10:49152`, Flags: `[SYN,ACK]`, Seq: 5000, Ack: 1001 | `tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.ack == 1001` | Expected Identical |
| **#7** | TCP ACK | `Flags: [ACK]`, Seq: 1001, Ack: 5001 | `tcp.flags.ack == 1 && tcp.flags.syn == 0` | Expected Identical |
| **#8** | HTTP Request | `GET /index.html HTTP/1.1`, Len: 130 B | `http.request.method == "GET"` | Expected Identical |
| **#9** | HTTP Response| `HTTP/1.1 200 OK`, Content-Length: 45 | `http.response.code == 200` | Expected Identical |
| **#10**| TCP FIN-ACK | `Flags: [FIN,ACK]` | `tcp.flags.fin == 1` | Expected Identical |
| **#11**| ICMP Echo Req | `Type: 8 (Echo Request)`, Code: 0, ID: 1, Seq: 1 | `icmp.type == 8 && icmp.code == 0` | Expected Identical |
| **#12**| ICMP Echo Rep | `Type: 0 (Echo Reply)`, Code: 0, ID: 1, Seq: 1 | `icmp.type == 0 && icmp.code == 0` | Expected Identical |
| **#13**| IPv6 UDP DNS | `2001:db8::10 -> 2001:db8::1`, Next Header: 17 | `ipv6.src == 2001:db8::10` | Expected Identical |
| **#14**| TLS Handshake | Record Type: `0x16`, Version: `0x0303` (TLS 1.2) | `tls.record.content_type == 22` | Expected Identical |
| **#15**| IPv4 Fragment | `flags: MF`, `frag: 0`, Proto: 17 | `ip.flags.mf == 1` | Expected Identical |
| **#16 - #40** | SYN Flood | 25 packets, `src: 10.0.0.99`, `dport: 80`, Flags: `[SYN]` | `ip.src == 10.0.0.99 && tcp.flags.syn == 1` (Count: 25) | Expected Identical |
| **#41 - #60** | Port Scan | 20 packets, `src: 10.0.0.88`, distinct dports 20-39 | `ip.src == 10.0.0.88 && tcp.flags.syn == 1` (Count: 20) | Expected Identical |

---

## 4. TShark CLI Verification Commands
If TShark is installed on your computer, execute these commands to independently verify the capture file:

```bash
# 1. Total packet count
tshark -r data/sample_traffic.pcap | wc -l
# Expected output: 60

# 2. Inspect ARP packets
tshark -r data/sample_traffic.pcap -Y "arp"
# Expected output: 2 packets (Who-has and Is-at)

# 3. Inspect DNS queries and answers
tshark -r data/sample_traffic.pcap -Y "dns" -T fields -e frame.number -e dns.qry.name -e dns.a
# Expected: example.com resolved to 93.184.216.34

# 4. Count SYN flood packets from attacker
tshark -r data/sample_traffic.pcap -Y "ip.src == 10.0.0.99 and tcp.flags.syn == 1" | wc -l
# Expected output: 25

# 5. Inspect port scan probes
tshark -r data/sample_traffic.pcap -Y "ip.src == 10.0.0.88" -T fields -e tcp.dstport
# Expected output: 20 distinct ports (20 through 39)
```
