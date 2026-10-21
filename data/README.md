# NetScope Test PCAP Dataset

This directory contains deterministic sample packet captures used for automated testing, offline demonstration, and academic Wireshark verification.

## Bundled Datasets

### 1. `sample_traffic.pcap` (60 Packets)
Generated deterministically with Scapy covering all required protocol families and anomaly scenarios:

| Packet IDs | Protocols | Scenario | Key Fields Verified |
|---|---|---|---|
| **#1 - #2** | ARP (Who-has, Is-at) | Layer 2 MAC resolution | `psrc: 192.168.1.10`, `pdst: 192.168.1.1`, opcode 1 & 2 |
| **#3 - #4** | DNS Query & Response | Domain name resolution | `example.com -> 93.184.216.34`, UDP port 53 |
| **#5 - #10** | TCP / HTTP | 3-way handshake + HTTP GET + 200 OK + FIN | Seq/Ack numbers, PA/FA flags, HTTP request/response line |
| **#11 - #12** | ICMP (Ping) | Ping Echo Request & Reply | ICMP Type 8 (Request) & Type 0 (Reply), code 0 |
| **#13** | IPv6 / DNS | IPv6 transport | `2001:db8::10 -> 2001:db8::1`, next-header UDP |
| **#14** | TLS (Client Hello) | Encrypted transport handshake | TLS Record type 0x16 (Handshake), Version TLS 1.2 |
| **#15** | IPv4 Fragment | Fragmented packet | `flags: MF`, `frag: 0`, protocol 17 |
| **#16 - #40** | TCP (SYN Flood) | Security Anomaly | 25 rapid standalone SYNs from `10.0.0.99` in 1.25s |
| **#41 - #60** | TCP (Port Scan) | Security Anomaly | 20 distinct destination port probes from `10.0.0.88` |

## Regenerating Sample Data
To regenerate or inspect the generation script, run:
```bash
python -m capture.generate_samples
```
