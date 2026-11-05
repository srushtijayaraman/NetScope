"""
NetScope X Traffic Replay & Demonstration Lab Subsystem
Provides safe, deterministic offline traffic replay across five distinct scenarios.
Allows step-by-step or timed execution with pause, resume, speed multiplier, and real-time
dashboard telemetry updates. Emits forensic events into the active investigation session.
"""

import time
import threading
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
)
from analyzer.parser import parse_packet


SCENARIO_METADATA = {
    "normal_traffic": {
        "id": "normal_traffic",
        "name": "Normal Mixed-Protocol Traffic",
        "description": "Standard enterprise network operations including ARP discovery, DNS resolutions, HTTP web requests, and TLS handshakes.",
        "expected_detection": "None (Clean baseline)",
        "expected_severity": "NORMAL",
        "category": "Baseline Operations",
        "packet_count": 32,
        "demonstrates": "Protocol distribution, healthy bidirectional TCP 3-way handshakes, and baseline KPI stability.",
    },
    "port_scan": {
        "id": "port_scan",
        "name": "Multi-Port Reconnaissance Probe",
        "description": "Attacker host 192.168.1.199 queries 22 distinct TCP/UDP ports on internal application server 192.168.1.50 in a rapid burst.",
        "expected_detection": "Heuristic: Potential Port Scan / Multi-Port Probe",
        "expected_severity": "MEDIUM",
        "category": "Reconnaissance",
        "packet_count": 36,
        "demonstrates": "Multi-port query heuristic, unique target tracking, port evidence links, and incident correlation.",
    },
    "syn_flood": {
        "id": "syn_flood",
        "name": "TCP SYN Half-Open Flood Pattern",
        "description": "External client 10.0.0.88 floods 28 rapid TCP SYN frames to web server 192.168.1.50:80 without returning ACK completions.",
        "expected_detection": "Heuristic: Suspicious SYN Burst (Possible SYN Flood)",
        "expected_severity": "HIGH",
        "category": "Denial of Service",
        "packet_count": 42,
        "demonstrates": "Incomplete handshake detection, TCP backlog queue risk, and direct evidence packet jumping.",
    },
    "traffic_spike": {
        "id": "traffic_spike",
        "name": "Volumetric Rate Spike Surge",
        "description": "Sudden arrival rate burst exceeding 180 packets/sec across cluster nodes, testing 1-second time-series bucketing.",
        "expected_detection": "Observation: Volumetric Packet Rate Spike",
        "expected_severity": "MEDIUM",
        "category": "Volumetric Anomaly",
        "packet_count": 190,
        "demonstrates": "Timeline rate spiking, observable fact vs suspicion separation, and PPS threshold alerts.",
    },
    "benign_burst": {
        "id": "benign_burst",
        "name": "Benign High-Volume Transfer",
        "description": "Scheduled legitimate database backup transfer of 50+ packets to single service port 443 with complete handshakes and continuous ACKs.",
        "expected_detection": "No Security Anomaly (False-Positive Suppression)",
        "expected_severity": "NORMAL",
        "category": "False-Positive Test",
        "packet_count": 55,
        "demonstrates": "Distinction between high volume and malicious behavior; complete ACKs prevent SYN flood false alarms.",
    },
}


def build_scenario_packets(scenario_id: str, base_time: float = None) -> list:
    """Constructs deterministic Scapy packets for the given demonstration scenario."""
    base_time = base_time or time.time()
    packets = []

    def eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", **kwargs):
        return Ether(src=src, dst=dst, **kwargs)

    if scenario_id == "normal_traffic":
        # 1. ARP Resolution
        p = eth(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.10", pdst="192.168.1.1")
        p.time = base_time + 0.05
        packets.append(p)

        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / ARP(op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.1", pdst="192.168.1.10")
        p.time = base_time + 0.08
        packets.append(p)

        # 2. DNS Query & Response
        p = eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=51200, dport=53) / DNS(rd=1, qd=DNSQR(qname="api.corp.internal"))
        p.time = base_time + 0.15
        packets.append(p)

        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=51200) / DNS(
            qr=1, rd=1, ra=1, qd=DNSQR(qname="api.corp.internal"), an=DNSRR(rrname="api.corp.internal", rdata="10.0.1.25", ttl=300)
        )
        p.time = base_time + 0.20
        packets.append(p)

        # 3. HTTP GET Exchange with 3-Way Handshake & Teardown
        # SYN
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="S", seq=1000)
        p.time = base_time + 0.30
        packets.append(p)
        # SYN-ACK
        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="10.0.1.25", dst="192.168.1.10") / TCP(sport=80, dport=52110, flags="SA", seq=7000, ack=1001)
        p.time = base_time + 0.35
        packets.append(p)
        # ACK
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="A", seq=1001, ack=7001)
        p.time = base_time + 0.38
        packets.append(p)
        # HTTP GET Request
        http_req = "GET /status HTTP/1.1\r\nHost: api.corp.internal\r\nUser-Agent: NetScopeClient/3.0\r\nAccept: */*\r\n\r\n"
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="PA", seq=1001, ack=7001) / Raw(load=http_req.encode())
        p.time = base_time + 0.45
        packets.append(p)
        # HTTP Response 200 OK
        http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"status\":\"healthy\",\"ok\":1}"
        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="10.0.1.25", dst="192.168.1.10") / TCP(sport=80, dport=52110, flags="PA", seq=7001, ack=1001 + len(http_req)) / Raw(load=http_resp.encode())
        p.time = base_time + 0.55
        packets.append(p)
        # ACK
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="A", seq=1001 + len(http_req), ack=7001 + len(http_resp))
        p.time = base_time + 0.60
        packets.append(p)
        # FIN-ACK Teardown
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="FA", seq=1001 + len(http_req), ack=7001 + len(http_resp))
        p.time = base_time + 0.70
        packets.append(p)
        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="10.0.1.25", dst="192.168.1.10") / TCP(sport=80, dport=52110, flags="FA", seq=7001 + len(http_resp), ack=1002 + len(http_req))
        p.time = base_time + 0.75
        packets.append(p)
        p = eth() / IP(src="192.168.1.10", dst="10.0.1.25") / TCP(sport=52110, dport=80, flags="A", seq=1002 + len(http_req), ack=7002 + len(http_resp))
        p.time = base_time + 0.80
        packets.append(p)

        # 4. HTTPS TLS Handshake
        tls_hello = b"\x16\x03\x01\x00\x45\x01\x00\x00\x41\x03\x03" + b"\xaa" * 32 + b"\x00\x00\x02\x00\x9c\x01\x00"
        p = eth() / IP(src="192.168.1.10", dst="104.16.132.229") / TCP(sport=53100, dport=443, flags="S", seq=2000)
        p.time = base_time + 0.90
        packets.append(p)
        p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="104.16.132.229", dst="192.168.1.10") / TCP(sport=443, dport=53100, flags="SA", seq=8000, ack=2001)
        p.time = base_time + 0.95
        packets.append(p)
        p = eth() / IP(src="192.168.1.10", dst="104.16.132.229") / TCP(sport=53100, dport=443, flags="A", seq=2001, ack=8001)
        p.time = base_time + 0.98
        packets.append(p)
        p = eth() / IP(src="192.168.1.10", dst="104.16.132.229") / TCP(sport=53100, dport=443, flags="PA", seq=2001, ack=8001) / Raw(load=tls_hello)
        p.time = base_time + 1.10
        packets.append(p)

        # 5. ICMP Ping
        for i in range(4):
            p = eth() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8, code=0, id=100, seq=i+1) / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
            p.time = base_time + 1.30 + (i * 0.25)
            packets.append(p)
            p = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="1.1.1.1", dst="192.168.1.10") / ICMP(type=0, code=0, id=100, seq=i+1) / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
            p.time = base_time + 1.35 + (i * 0.25)
            packets.append(p)

    elif scenario_id == "port_scan":
        # Attacker 192.168.1.199 probes 20+ distinct ports on 192.168.1.50
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        for i, port in enumerate(ports):
            p_syn = eth(src="00:de:ad:be:ef:01") / IP(src="192.168.1.199", dst="192.168.1.50") / TCP(
                sport=40000 + i, dport=port, flags="S", seq=1000 + i * 10
            )
            p_syn.time = base_time + 0.1 + (i * 0.08)
            packets.append(p_syn)

            # Target responds RST on closed ports, SYN-ACK on open ports 80 and 443
            if port in (80, 443):
                p_resp = eth(src="00:aa:bb:cc:dd:ee", dst="00:de:ad:be:ef:01") / IP(src="192.168.1.50", dst="192.168.1.199") / TCP(
                    sport=port, dport=40000 + i, flags="SA", seq=5000, ack=1001 + i * 10
                )
            else:
                p_resp = eth(src="00:aa:bb:cc:dd:ee", dst="00:de:ad:be:ef:01") / IP(src="192.168.1.50", dst="192.168.1.199") / TCP(
                    sport=port, dport=40000 + i, flags="RA", seq=0, ack=1001 + i * 10
                )
            p_resp.time = base_time + 0.12 + (i * 0.08)
            packets.append(p_resp)

    elif scenario_id == "syn_flood":
        # Attacker 10.0.0.88 floods 28 rapid TCP SYN frames to 192.168.1.50:80 without returning ACK
        for i in range(28):
            p_syn = eth(src="00:aa:00:ff:11:22") / IP(src="10.0.0.88", dst="192.168.1.50") / TCP(
                sport=30000 + i, dport=80, flags="S", seq=50000 + i * 100
            )
            p_syn.time = base_time + 0.05 + (i * 0.04)
            packets.append(p_syn)

            # Web server attempts SYN-ACK reply
            if i % 2 == 0:
                p_sa = eth(src="00:aa:bb:cc:dd:ee", dst="00:aa:00:ff:11:22") / IP(src="192.168.1.50", dst="10.0.0.88") / TCP(
                    sport=80, dport=30000 + i, flags="SA", seq=90000 + i * 100, ack=50001 + i * 100
                )
                p_sa.time = base_time + 0.07 + (i * 0.04)
                packets.append(p_sa)

    elif scenario_id == "traffic_spike":
        # Sudden arrival rate burst of 180+ packets across a 1-second interval
        for i in range(180):
            sip = f"192.168.1.{10 + (i % 5)}"
            dip = f"192.168.1.{50 + (i % 3)}"
            p = eth() / IP(src=sip, dst=dip) / UDP(sport=50000 + i, dport=9000) / Raw(load=b"X" * 64)
            p.time = base_time + 0.5 + (i * 0.004)  # 180 packets in ~0.72 sec
            packets.append(p)

    elif scenario_id == "benign_burst":
        # Complete TCP session with 50+ packets, handshakes, streaming data, and ACKs
        # SYN / SYN-ACK / ACK
        p_syn = eth() / IP(src="192.168.1.20", dst="192.168.1.100") / TCP(sport=55000, dport=443, flags="S", seq=10000)
        p_syn.time = base_time + 0.05
        packets.append(p_syn)
        p_sa = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="192.168.1.100", dst="192.168.1.20") / TCP(sport=443, dport=55000, flags="SA", seq=20000, ack=10001)
        p_sa.time = base_time + 0.08
        packets.append(p_sa)
        p_ack = eth() / IP(src="192.168.1.20", dst="192.168.1.100") / TCP(sport=55000, dport=443, flags="A", seq=10001, ack=20001)
        p_ack.time = base_time + 0.10
        packets.append(p_ack)

        seq_c = 10001
        ack_s = 20001
        for i in range(25):
            payload = b"BACKUP_DATA_SEGMENT_" + str(i).encode() + (b"0" * 400)
            p_data = eth() / IP(src="192.168.1.20", dst="192.168.1.100") / TCP(
                sport=55000, dport=443, flags="PA", seq=seq_c, ack=ack_s
            ) / Raw(load=payload)
            p_data.time = base_time + 0.15 + (i * 0.05)
            packets.append(p_data)
            seq_c += len(payload)

            p_ack_back = eth(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src="192.168.1.100", dst="192.168.1.20") / TCP(
                sport=443, dport=55000, flags="A", seq=ack_s, ack=seq_c
            )
            p_ack_back.time = base_time + 0.17 + (i * 0.05)
            packets.append(p_ack_back)

    # Sort packets strictly by timestamp
    packets.sort(key=lambda pkt: float(pkt.time))
    return packets


class ReplayEngine:
    """Thread-safe stateful player for deterministic traffic scenarios."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = "IDLE"  # IDLE, RUNNING, PAUSED, STOPPED, COMPLETED
        self.scenario_id = None
        self.speed = 2.0     # 1x, 2x, 5x, 10x, 0 for instant
        self.progress_pct = 0.0
        self.current_index = 0
        self.total_packets = 0
        self.start_time = 0.0
        self.elapsed_seconds = 0.0
        self.rule_hits = []

        self._thread = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused initially
        self._packet_callback = None

    def get_status(self) -> dict:
        with self.lock:
            meta = SCENARIO_METADATA.get(self.scenario_id, {})
            return {
                "state": self.state,
                "scenario_id": self.scenario_id,
                "scenario_name": meta.get("name", "None"),
                "expected_detection": meta.get("expected_detection", "None"),
                "expected_severity": meta.get("expected_severity", "NORMAL"),
                "speed": self.speed,
                "progress_pct": round(self.progress_pct, 1),
                "current_packet": self.current_index,
                "total_packets": self.total_packets,
                "elapsed_seconds": round(self.elapsed_seconds, 2),
                "rule_hits": list(self.rule_hits),
            }

    def start(self, scenario_id: str, packet_callback, speed: float = 2.0) -> dict:
        """Starts a new deterministic scenario replay in a background thread."""
        if scenario_id not in SCENARIO_METADATA:
            raise ValueError(f"Unknown scenario ID: {scenario_id}")

        self.stop()  # Clean up any existing run

        with self.lock:
            self.scenario_id = scenario_id
            self.speed = max(0.1, float(speed)) if speed != 0 else 0
            self.state = "RUNNING"
            self.progress_pct = 0.0
            self.current_index = 0
            self.rule_hits = []
            self.start_time = time.time()
            self.elapsed_seconds = 0.0
            self._packet_callback = packet_callback
            self._stop_event.clear()
            self._pause_event.set()

        # Build packets
        raw_packets = build_scenario_packets(scenario_id, base_time=self.start_time)
        self.total_packets = len(raw_packets)

        if self.speed == 0:
            self._worker(raw_packets)
        else:
            self._thread = threading.Thread(
                target=self._worker,
                args=(raw_packets,),
                daemon=True,
                name=f"ReplayWorker-{scenario_id}"
            )
            self._thread.start()
        return self.get_status()

    def pause(self) -> dict:
        with self.lock:
            if self.state == "RUNNING":
                self.state = "PAUSED"
                self._pause_event.clear()
        return self.get_status()

    def resume(self) -> dict:
        with self.lock:
            if self.state == "PAUSED":
                self.state = "RUNNING"
                self._pause_event.set()
        return self.get_status()

    def stop(self) -> dict:
        self._stop_event.set()
        self._pause_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        with self.lock:
            self.state = "STOPPED"
        return self.get_status()

    def reset(self) -> dict:
        self.stop()
        with self.lock:
            self.state = "IDLE"
            self.scenario_id = None
            self.progress_pct = 0.0
            self.current_index = 0
            self.total_packets = 0
            self.elapsed_seconds = 0.0
            self.rule_hits = []
        return self.get_status()

    def _worker(self, raw_packets: list):
        start_ts = time.time()
        prev_pkt_time = float(raw_packets[0].time) if raw_packets else start_ts

        for idx, pkt in enumerate(raw_packets, start=1):
            if self._stop_event.is_set():
                break

            # Wait if paused
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            # Pace replay according to speed multiplier
            pkt_time = float(pkt.time)
            if self.speed > 0:
                delta = pkt_time - prev_pkt_time
                if delta > 0:
                    delay = min(0.3, delta / self.speed)
                    if delay > 0.001:
                        time.sleep(delay)
            prev_pkt_time = pkt_time

            # Parse and deliver packet record
            record = parse_packet(pkt, packet_id=idx)
            if self._packet_callback:
                self._packet_callback(record)

            with self.lock:
                self.current_index = idx
                self.elapsed_seconds = time.time() - start_ts
                self.progress_pct = (idx / self.total_packets) * 100.0

        with self.lock:
            if not self._stop_event.is_set():
                self.state = "COMPLETED"
                self.progress_pct = 100.0
