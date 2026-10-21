"""
NetScope Packet Parser
Extracts network, transport, and application layer metadata into a normalized, structured representation.
Handles Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, HTTP, TLS, fragments, and malformed packets.
Guarantees robust exception safety and zero uncaught crashes on corrupt frames.
"""

import warnings
from datetime import datetime, timezone
from scapy.packet import Packet
from analyzer.protocol_classifier import classify_application_protocol

# Silence upstream Scapy 2.8 PacketListField deprecation warnings on DNS fields
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"scapy\..*")

TCP_FLAG_NAMES = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}

ICMPV6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
}

DNS_QTYPES = {
    1: "A (IPv4 Host)",
    2: "NS (Authoritative Name Server)",
    5: "CNAME (Canonical Name)",
    6: "SOA (Start of Authority)",
    12: "PTR (Pointer / Reverse DNS)",
    15: "MX (Mail Exchange)",
    16: "TXT (Text Record)",
    28: "AAAA (IPv6 Host)",
    33: "SRV (Service Locator)",
    255: "ANY (All Records)",
}

DNS_RCODES = {
    0: "NOERROR (Success)",
    1: "FORMERR (Format Error)",
    2: "SERVFAIL (Server Failure)",
    3: "NXDOMAIN (Non-Existent Domain)",
    4: "NOTIMP (Not Implemented)",
    5: "REFUSED (Query Refused)",
}


def parse_tcp_flags(flags_val) -> list[str]:
    """Decodes integer or Scapy FlagValue into list of flag strings."""
    if flags_val is None:
        return []
    try:
        int_val = int(flags_val)
        return [name for bit, name in TCP_FLAG_NAMES.items() if (int_val & bit)]
    except (ValueError, TypeError):
        str_val = str(flags_val).upper()
        mapping = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
        return [mapping[c] for c in str_val if c in mapping]


def parse_packet(packet: Packet, packet_id: int, capture_id: str = "default", base_timestamp: float | None = None) -> dict:
    """
    Parses a single Scapy packet into a normalized, safe dictionary.
    Guarantees no unhandled exceptions and complete defensive attribute checking.
    """
    try:
        raw_wire_len = len(packet)
    except Exception:
        raw_wire_len = 0

    # Extract timestamp safely
    pkt_time = getattr(packet, "time", None)
    if pkt_time is not None:
        try:
            ts_float = float(pkt_time)
            ts_iso = datetime.fromtimestamp(ts_float, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception:
            ts_float = 0.0
            ts_iso = "1970-01-01 00:00:00.000"
    else:
        ts_float = datetime.now(timezone.utc).timestamp()
        ts_iso = datetime.fromtimestamp(ts_float, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    relative_sec = round(ts_float - base_timestamp, 4) if (base_timestamp is not None and ts_float >= base_timestamp) else 0.0

    record = {
        "packet_id": packet_id,
        "capture_id": capture_id,
        "flow_id": None,
        "timestamp": ts_float,
        "timestamp_iso": ts_iso,
        "relative_time_sec": relative_sec,
        "packet_length": raw_wire_len,
        "captured_length": raw_wire_len,
        "source_mac": None,
        "destination_mac": None,
        "source_ip": None,
        "destination_ip": None,
        "network_protocol": "Unknown",
        "transport_protocol": "None",
        "source_port": None,
        "destination_port": None,
        "application_protocol": "Unknown",
        "tcp_flags": [],
        "tcp_flags_hex": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "summary": "",
        "parsing_status": "Parsed",
        "details": {
            "link_layer": {},
            "network_layer": {},
            "transport_layer": {},
            "application_layer": {},
        },
    }

    try:
        # 1. Link Layer (Ethernet, etc.)
        if packet.haslayer("Ethernet"):
            eth = packet["Ethernet"]
            record["source_mac"] = str(getattr(eth, "src", "")) or None
            record["destination_mac"] = str(getattr(eth, "dst", "")) or None
            record["details"]["link_layer"] = {
                "type": "Ethernet",
                "source_mac": record["source_mac"],
                "destination_mac": record["destination_mac"],
                "ether_type": hex(getattr(eth, "type", 0)),
            }

        # 2. Network Layer
        if packet.haslayer("ARP"):
            arp = packet["ARP"]
            record["network_protocol"] = "ARP"
            record["source_ip"] = str(getattr(arp, "psrc", "")) or None
            record["destination_ip"] = str(getattr(arp, "pdst", "")) or None
            op_code = getattr(arp, "op", 1)
            op_desc = "who-has" if op_code == 1 else ("is-at" if op_code == 2 else f"op-{op_code}")
            record["details"]["network_layer"] = {
                "protocol": "ARP",
                "operation": op_desc,
                "sender_mac": str(getattr(arp, "hwsrc", "")),
                "sender_ip": record["source_ip"],
                "target_mac": str(getattr(arp, "hwdst", "")),
                "target_ip": record["destination_ip"],
            }
            record["summary"] = f"ARP {op_desc} {record['destination_ip']} tell {record['source_ip']}"

        elif packet.haslayer("IP"):
            ip = packet["IP"]
            record["network_protocol"] = "IPv4"
            record["source_ip"] = str(getattr(ip, "src", "")) or None
            record["destination_ip"] = str(getattr(ip, "dst", "")) or None
            frag_offset = getattr(ip, "frag", 0)
            flags = getattr(ip, "flags", 0)
            is_fragment = (frag_offset > 0) or ("MF" in str(flags))
            if is_fragment:
                record["parsing_status"] = "Fragment"

            record["details"]["network_layer"] = {
                "protocol": "IPv4",
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "ttl": getattr(ip, "ttl", None),
                "identification": getattr(ip, "id", None),
                "header_length": getattr(ip, "ihl", None),
                "fragment_offset": frag_offset,
                "flags": str(flags),
                "checksum": hex(getattr(ip, "chksum", 0)) if getattr(ip, "chksum", None) is not None else None,
            }

        elif packet.haslayer("IPv6"):
            ipv6 = packet["IPv6"]
            record["network_protocol"] = "IPv6"
            record["source_ip"] = str(getattr(ipv6, "src", "")) or None
            record["destination_ip"] = str(getattr(ipv6, "dst", "")) or None
            record["details"]["network_layer"] = {
                "protocol": "IPv6",
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "hop_limit": getattr(ipv6, "hlim", None),
                "traffic_class": getattr(ipv6, "tc", None),
                "next_header": getattr(ipv6, "nh", None),
                "flow_label": getattr(ipv6, "fl", None),
            }

        # 3. Transport Layer
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            record["transport_protocol"] = "TCP"
            record["source_port"] = int(getattr(tcp, "sport", 0))
            record["destination_port"] = int(getattr(tcp, "dport", 0))
            raw_flags = getattr(tcp, "flags", None)
            record["tcp_flags"] = parse_tcp_flags(raw_flags)
            try:
                record["tcp_flags_hex"] = hex(int(raw_flags))
            except Exception:
                record["tcp_flags_hex"] = None
            record["tcp_seq"] = int(getattr(tcp, "seq", 0))
            record["tcp_ack"] = int(getattr(tcp, "ack", 0))
            flags_str = ",".join(record["tcp_flags"]) if record["tcp_flags"] else "NONE"
            
            record["details"]["transport_layer"] = {
                "protocol": "TCP",
                "source_port": record["source_port"],
                "destination_port": record["destination_port"],
                "sequence_number": record["tcp_seq"],
                "acknowledgment_number": record["tcp_ack"],
                "flags": record["tcp_flags"],
                "flags_hex": record["tcp_flags_hex"],
                "window_size": getattr(tcp, "window", None),
                "checksum": hex(getattr(tcp, "chksum", 0)) if getattr(tcp, "chksum", None) is not None else None,
                "urgent_pointer": getattr(tcp, "urgptr", None),
            }
            record["summary"] = f"{record['source_ip']}:{record['source_port']} -> {record['destination_ip']}:{record['destination_port']} [{flags_str}] Seq={record['tcp_seq']} Ack={record['tcp_ack']}"

        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            record["transport_protocol"] = "UDP"
            record["source_port"] = int(getattr(udp, "sport", 0))
            record["destination_port"] = int(getattr(udp, "dport", 0))
            record["details"]["transport_layer"] = {
                "protocol": "UDP",
                "source_port": record["source_port"],
                "destination_port": record["destination_port"],
                "length": getattr(udp, "len", None),
                "checksum": hex(getattr(udp, "chksum", 0)) if getattr(udp, "chksum", None) is not None else None,
            }
            record["summary"] = f"{record['source_ip']}:{record['source_port']} -> {record['destination_ip']}:{record['destination_port']} Len={getattr(udp, 'len', 0)}"

        elif packet.haslayer("ICMP"):
            icmp = packet["ICMP"]
            record["transport_protocol"] = "ICMP"
            type_num = getattr(icmp, "type", 0)
            code_num = getattr(icmp, "code", 0)
            type_desc = ICMP_TYPES.get(type_num, f"Type {type_num}")
            icmp_id = getattr(icmp, "id", None)
            icmp_seq = getattr(icmp, "seq", None)
            record["details"]["transport_layer"] = {
                "protocol": "ICMP",
                "type": type_num,
                "type_name": type_desc,
                "code": code_num,
                "id": icmp_id,
                "sequence": icmp_seq,
                "checksum": hex(getattr(icmp, "chksum", 0)) if getattr(icmp, "chksum", None) is not None else None,
            }
            id_seq_info = f" id={icmp_id} seq={icmp_seq}" if icmp_id is not None else ""
            record["summary"] = f"ICMP {type_desc} (code {code_num}){id_seq_info} {record['source_ip']} -> {record['destination_ip']}"

        elif packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply") or "ICMPv6" in packet.summary():
            record["transport_protocol"] = "ICMPv6"
            record["details"]["transport_layer"] = {"protocol": "ICMPv6", "summary": packet.summary()}
            record["summary"] = f"ICMPv6 {record['source_ip']} -> {record['destination_ip']}"

        # 4. Application Layer
        app_proto = classify_application_protocol(
            packet, record["transport_protocol"], record["source_port"], record["destination_port"]
        )
        record["application_protocol"] = app_proto

        if packet.haslayer("DNS"):
            dns = packet["DNS"]
            qr = getattr(dns, "qr", 0)
            is_response = (qr == 1)
            tx_id = getattr(dns, "id", 0)
            rcode_val = getattr(dns, "rcode", 0)
            rcode_desc = DNS_RCODES.get(rcode_val, f"RCODE {rcode_val}")

            # Safely handle Scapy PacketListField without triggering deprecation warnings
            qname = ""
            qtype_desc = "Unknown"
            try:
                qd_list = getattr(dns, "qd", None)
                if qd_list:
                    first_qd = qd_list[0] if isinstance(qd_list, (list, tuple)) and len(qd_list) > 0 else qd_list
                    qn = getattr(first_qd, "qname", b"")
                    qname = qn.decode(errors="replace") if isinstance(qn, bytes) else str(qn)
                    qt = getattr(first_qd, "qtype", 1)
                    qtype_desc = DNS_QTYPES.get(qt, f"Type {qt}")
            except Exception:
                qname = ""

            answers = []
            if is_response:
                try:
                    an_layer = getattr(dns, "an", None)
                    if an_layer:
                        rr_list = list(an_layer) if isinstance(an_layer, (list, tuple)) else [an_layer]
                        for rr in rr_list[:8]:
                            rdata = getattr(rr, "rdata", "")
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors="replace")
                            rr_type = getattr(rr, "type", 1)
                            rr_type_name = DNS_QTYPES.get(rr_type, f"Type {rr_type}").split(" ")[0]
                            answers.append(f"{rr_type_name}: {rdata}")
                except Exception:
                    pass

            flags_info = []
            if getattr(dns, "aa", 0): flags_info.append("Authoritative")
            if getattr(dns, "tc", 0): flags_info.append("Truncated")
            if getattr(dns, "rd", 0): flags_info.append("Recursion Desired")
            if getattr(dns, "ra", 0): flags_info.append("Recursion Available")

            record["details"]["application_layer"] = {
                "protocol": "DNS",
                "transaction_id": hex(tx_id),
                "is_response": is_response,
                "message_type": "Response" if is_response else "Query",
                "query_name": qname,
                "query_type": qtype_desc,
                "rcode": rcode_val,
                "rcode_description": rcode_desc,
                "dns_flags": flags_info,
                "answers": answers,
            }
            direction = "Resp" if is_response else "Query"
            first_ans = f" -> {answers[0]}" if answers else ""
            record["summary"] = f"DNS {direction} (ID {hex(tx_id)}) {qname} [{qtype_desc.split(' ')[0]}]{first_ans}"

        elif app_proto == "HTTP" and packet.haslayer("Raw"):
            try:
                raw_data = bytes(packet["Raw"].load)
                first_line = raw_data.split(b"\r\n")[0].decode(errors="replace")
                record["details"]["application_layer"] = {
                    "protocol": "HTTP",
                    "request_line": first_line,
                    "payload_length_bytes": len(raw_data),
                }
                record["summary"] = f"HTTP {first_line}"
            except Exception:
                pass

        elif "TLS" in app_proto:
            record["details"]["application_layer"] = {
                "protocol": "TLS",
                "note": "Encrypted Transport Layer Security (TLS) record. Payload is encrypted; metadata only.",
            }
            if not record["summary"]:
                record["summary"] = f"TLS {record['source_ip']}:{record['source_port']} -> {record['destination_ip']}:{record['destination_port']}"

        # Default fallback summary if still empty
        if not record["summary"]:
            if record["source_ip"] and record["destination_ip"]:
                record["summary"] = f"{record['network_protocol']} {record['source_ip']} -> {record['destination_ip']} [{record['transport_protocol']}]"
            else:
                record["summary"] = f"{record['network_protocol']} Frame (Len={record['packet_length']})"

    except Exception as exc:
        record["parsing_status"] = "Malformed"
        record["summary"] = f"Malformed Frame: {str(exc)}"
        record["details"]["error"] = str(exc)

    return record
