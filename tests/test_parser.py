"""
NetScope Parser Unit Tests
Validates parsing and classification of Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, fragments, and malformed packets.
"""

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from analyzer.parser import parse_packet, parse_tcp_flags
from analyzer.protocol_classifier import classify_application_protocol


def eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=None):
    kw = {"src": src, "dst": dst}
    if type is not None:
        kw["type"] = type
    return Ether(**kw)


def test_parse_tcp_syn_packet():
    p = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S", seq=100)
    p.time = 1700000000.0
    rec = parse_packet(p, packet_id=1)

    assert rec["packet_id"] == 1
    assert rec["source_ip"] == "10.0.0.1"
    assert rec["destination_ip"] == "10.0.0.2"
    assert rec["network_protocol"] == "IPv4"
    assert rec["transport_protocol"] == "TCP"
    assert rec["source_port"] == 1234
    assert rec["destination_port"] == 80
    assert "SYN" in rec["tcp_flags"]
    assert rec["parsing_status"] == "Parsed"
    assert rec["details"]["transport_layer"]["sequence_number"] == 100


def test_parse_udp_dns_packet():
    p = eth() / IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
    p.time = 1700000001.0
    rec = parse_packet(p, packet_id=2)

    assert rec["network_protocol"] == "IPv4"
    assert rec["transport_protocol"] == "UDP"
    assert rec["application_protocol"] == "DNS"
    assert rec["details"]["application_layer"]["protocol"] == "DNS"
    assert "google.com" in rec["details"]["application_layer"]["query_name"]


def test_parse_arp_packet():
    p = eth(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.10",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.1"
    )
    rec = parse_packet(p, packet_id=3)

    assert rec["network_protocol"] == "ARP"
    assert rec["transport_protocol"] == "None"
    assert rec["source_ip"] == "192.168.1.10"
    assert rec["destination_ip"] == "192.168.1.1"
    assert rec["details"]["network_layer"]["operation"] == "who-has"


def test_parse_icmp_packet():
    p = eth() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(type=8, code=0)
    rec = parse_packet(p, packet_id=4)

    assert rec["network_protocol"] == "IPv4"
    assert rec["transport_protocol"] == "ICMP"
    assert rec["details"]["transport_layer"]["type_name"] == "Echo Request"


def test_parse_ipv6_packet():
    p = eth(type=0x86dd) / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=4000, dport=5000)
    rec = parse_packet(p, packet_id=5)

    assert rec["network_protocol"] == "IPv6"
    assert rec["source_ip"] == "fe80::1"
    assert rec["destination_ip"] == "fe80::2"


def test_parse_fragment_packet():
    p = eth() / IP(src="10.0.0.1", dst="10.0.0.2", flags="MF", frag=10, proto=17) / Raw(b"fragmentdata")
    rec = parse_packet(p, packet_id=6)

    assert rec["parsing_status"] == "Fragment"
    assert rec["details"]["network_layer"]["fragment_offset"] == 10


def test_parse_http_payload():
    payload = b"GET /api/v1/test HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=payload)
    rec = parse_packet(p, packet_id=7)

    assert rec["application_protocol"] == "HTTP"
    assert "GET /api/v1/test HTTP/1.1" in rec["summary"]


def test_parse_tls_handshake_payload():
    # TLS Client Hello signature (record type 0x16, version 0x0303)
    tls_payload = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"\x00" * 16
    p = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="PA") / Raw(load=tls_payload)
    rec = parse_packet(p, packet_id=8)

    assert rec["application_protocol"] == "TLS"


def test_tcp_flag_decoder():
    flags = parse_tcp_flags(0x12)  # SYN (0x02) | ACK (0x10)
    assert "SYN" in flags
    assert "ACK" in flags
    assert len(flags) == 2


def test_defensive_missing_fields():
    """Ensure raw or unexpected layers do not crash the parser."""
    p = eth() / Raw(b"randomrawbyteswithoutip")
    rec = parse_packet(p, packet_id=9)

    assert rec["packet_id"] == 9
    assert rec["network_protocol"] == "Unknown"
    assert rec["transport_protocol"] == "None"
    assert rec["parsing_status"] == "Parsed"


def test_parse_dns_query_and_response_details():
    """Verify deep DNS decoding: transaction ID, query types, and answer extraction."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    # DNS query
    dns_query_pkt = eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53530, dport=53) / DNS(
        id=0x1A2B, qr=0, qd=DNSQR(qname="antigravity.dev", qtype="A")
    )
    rec_q = parse_packet(dns_query_pkt, packet_id=10, base_timestamp=100.0)
    assert rec_q["application_protocol"] == "DNS"
    assert rec_q["details"]["application_layer"]["protocol"] == "DNS"
    assert rec_q["details"]["application_layer"]["transaction_id"] == "0x1a2b"
    assert rec_q["details"]["application_layer"]["query_name"] == "antigravity.dev."
    assert rec_q["details"]["application_layer"]["query_type"].startswith("A")
    assert rec_q["relative_time_sec"] >= 0.0

    # DNS response with answer
    dns_resp_pkt = eth() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=53530) / DNS(
        id=0x1A2B, qr=1, rcode=0,
        qd=DNSQR(qname="antigravity.dev", qtype="A"),
        an=DNSRR(rrname="antigravity.dev", type="A", rdata="142.250.190.46", ttl=300)
    )
    rec_r = parse_packet(dns_resp_pkt, packet_id=11)
    assert rec_r["details"]["application_layer"]["rcode"] == 0
    assert "NOERROR" in rec_r["details"]["application_layer"]["rcode_description"]
    assert len(rec_r["details"]["application_layer"]["answers"]) >= 1
    assert "142.250.190.46" in rec_r["details"]["application_layer"]["answers"][0]


def test_parse_corrupt_packet_safe():
    """Ensure non-packet or severely corrupted objects return Error safely without raising."""
    rec = parse_packet("not_a_scapy_packet", packet_id=99)
    assert rec["packet_id"] == 99
    assert rec["parsing_status"] == "Malformed"
    assert "error" in rec["details"]


