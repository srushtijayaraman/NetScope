"""
Utility script to generate deterministic sample PCAP data for testing and offline demo.
"""

import os
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap
)


def generate_sample_pcap(output_path: str = "data/sample_traffic.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    base_time = 1700000000.0

    def eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=None):
        kw = {"src": src, "dst": dst}
        if type is not None:
            kw["type"] = type
        return Ether(**kw)

    # 1. ARP Resolution (192.168.1.10 asking for 192.168.1.1)
    p_arp_req = eth(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.10",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.1"
    )
    p_arp_req.time = base_time + 0.01
    packets.append(p_arp_req)

    p_arp_rep = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / ARP(
        op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.1",
        hwdst="00:11:22:33:44:55", pdst="192.168.1.10"
    )
    p_arp_rep.time = base_time + 0.02
    packets.append(p_arp_rep)

    # 2. DNS Query & Response (example.com)
    p_dns_req = eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53210, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    p_dns_req.time = base_time + 0.05
    packets.append(p_dns_req)

    p_dns_rep = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=53210) / DNS(
        qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", rdata="93.184.216.34", ttl=300)
    )
    p_dns_rep.time = base_time + 0.08
    packets.append(p_dns_rep)

    # 3. HTTP 3-Way Handshake, Request, Response, Teardown
    p_syn = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S", seq=1000)
    p_syn.time = base_time + 0.10
    packets.append(p_syn)

    p_synack = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
    p_synack.time = base_time + 0.12
    packets.append(p_synack)

    p_ack = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    p_ack.time = base_time + 0.13
    packets.append(p_ack)

    http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope/1.0\r\n\r\n"
    p_http_req = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) / Raw(load=http_req)
    p_http_req.time = base_time + 0.15
    packets.append(p_http_req)

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body><h1>NetScope Academic</h1></body></html>"
    p_http_resp = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1001 + len(http_req)) / Raw(load=http_resp)
    p_http_resp.time = base_time + 0.20
    packets.append(p_http_resp)

    p_fin = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="FA", seq=1001 + len(http_req), ack=5001 + len(http_resp))
    p_fin.time = base_time + 0.22
    packets.append(p_fin)

    # 4. ICMP Ping Echo Request and Reply
    p_ping_req = eth() / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8, code=0, id=1, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
    p_ping_req.time = base_time + 0.30
    packets.append(p_ping_req)

    p_ping_rep = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=0, code=0, id=1, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
    p_ping_rep.time = base_time + 0.32
    packets.append(p_ping_rep)

    # 5. IPv6 Packet
    p_ipv6 = eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=0x86dd) / IPv6(src="2001:db8::10", dst="2001:db8::1") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="ipv6.org"))
    p_ipv6.time = base_time + 0.40
    packets.append(p_ipv6)

    # 6. TLS Handshake Packet (Client Hello)
    tls_client_hello_bytes = bytes([
        0x16, 0x03, 0x01, 0x00, 0x30,
        0x01, 0x00, 0x00, 0x2c,
        0x03, 0x03
    ]) + b"\x00" * 38
    p_tls = eth() / IP(src="192.168.1.10", dst="104.244.42.1") / TCP(sport=49200, dport=443, flags="PA") / Raw(load=tls_client_hello_bytes)
    p_tls.time = base_time + 0.50
    packets.append(p_tls)

    # 7. IPv4 Fragment
    p_frag = eth() / IP(src="192.168.1.10", dst="192.168.1.50", flags="MF", frag=0, proto=17) / Raw(b"fragment_data_part1")
    p_frag.time = base_time + 0.60
    packets.append(p_frag)

    # 8. Simulated Anomaly: SYN Flood from 10.0.0.99 (25 SYNs in 2 seconds)
    for i in range(25):
        p_syn_burst = eth(src="00:99:99:99:99:99") / IP(src="10.0.0.99", dst="192.168.1.100") / TCP(sport=10000 + i, dport=80, flags="S", seq=i * 100)
        p_syn_burst.time = base_time + 1.0 + (i * 0.05)
        packets.append(p_syn_burst)

    # 9. Simulated Anomaly: Port Scan from 10.0.0.88 (probes 20 distinct ports on 192.168.1.200)
    for p in range(20, 40):
        p_scan = eth(src="00:88:88:88:88:88") / IP(src="10.0.0.88", dst="192.168.1.200") / TCP(sport=40000, dport=p, flags="S")
        p_scan.time = base_time + 2.5 + ((p - 20) * 0.05)
        packets.append(p_scan)

    wrpcap(output_path, packets)
    return len(packets)


if __name__ == "__main__":
    count = generate_sample_pcap()
    print(f"Generated {count} packets.")
