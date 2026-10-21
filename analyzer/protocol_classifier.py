"""
NetScope Protocol Classifier
Inspects packet layers and payloads to identify network, transport, and application protocols
without relying purely on standard port numbers.
"""

def classify_application_protocol(packet, transport_proto: str, sport: int | None, dport: int | None) -> str:
    """
    Classifies the application layer protocol using packet payload inspection
    combined with contextual port hints, adhering to strict classification rules:
    never claim certainty based on port alone without payload validation.
    """
    if not transport_proto:
        return "None"
        
    ports = {sport, dport} - {None}
    
    # 1. DNS detection via Scapy layer or payload inspection
    if packet.haslayer("DNS"):
        return "DNS"
    if 53 in ports or 5353 in ports:
        if packet.haslayer("Raw"):
            # Check for basic DNS header structure if raw
            raw_bytes = bytes(packet["Raw"].load)
            if len(raw_bytes) >= 12:
                # DNS ID + flags
                return "DNS"
        elif packet.haslayer("UDP") or packet.haslayer("TCP"):
            # Known DNS port with no raw payload may be empty query or setup
            return "DNS"

    # 2. DHCP detection
    if packet.haslayer("DHCP") or packet.haslayer("BOOTP"):
        return "DHCP"
    if {67, 68}.intersection(ports):
        return "DHCP"

    # 3. NTP detection
    if packet.haslayer("NTP") or 123 in ports:
        if packet.haslayer("Raw"):
            raw_bytes = bytes(packet["Raw"].load)
            if len(raw_bytes) >= 48:
                return "NTP"
        return "NTP"

    # 4. Inspect payload for TCP or UDP
    if packet.haslayer("Raw"):
        payload = bytes(packet["Raw"].load)
        if not payload:
            return "Unknown"

        # TLS / SSL Handshake inspection (RFC 5246 / RFC 8446)
        # Content types: 20 (ChangeCipherSpec), 21 (Alert), 22 (Handshake), 23 (Application Data)
        # Version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)
        if len(payload) >= 5:
            record_type = payload[0]
            major_ver = payload[1]
            minor_ver = payload[2]
            if record_type in (20, 21, 22, 23) and major_ver == 3 and minor_ver in (0, 1, 2, 3, 4):
                return "TLS"

        # HTTP Inspection (Textual methods or HTTP response status line)
        http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
        if any(payload.startswith(m) for m in http_methods) or payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
            return "HTTP"

        # SSH Detection
        if payload.startswith(b"SSH-"):
            return "SSH"

        # FTP Detection
        if payload.startswith(b"220 ") or payload.startswith(b"USER ") or payload.startswith(b"PASS "):
            if 21 in ports:
                return "FTP"

        # SMTP Detection
        if (payload.startswith(b"220 ") or payload.startswith(b"HELO ") or payload.startswith(b"EHLO ")) and 25 in ports:
            return "SMTP"

    # If port matches standard service but payload is absent or encrypted/opaque:
    if 443 in ports or 8443 in ports:
        return "TLS (Inferred)" if not packet.haslayer("Raw") else "Unknown"
    if 80 in ports or 8080 in ports:
        return "HTTP (Inferred)" if not packet.haslayer("Raw") else "Unknown"
    if 22 in ports:
        return "SSH (Inferred)"
    if 21 in ports:
        return "FTP (Inferred)"

    return "Unknown"
