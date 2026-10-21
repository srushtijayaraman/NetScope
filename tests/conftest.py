"""
NetScope Pytest Fixtures
Provides a test Flask client and deterministic synthetic packet fixtures.
"""

import os
import sys
import tempfile
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap
from app import create_app
from config import TestConfig
from storage.database import DatabaseManager


@pytest.fixture
def app():
    test_db = os.path.join(tempfile.gettempdir(), f"netscope_test_{os.getpid()}.db")
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except Exception:
            pass

    TestConfig.DATABASE_PATH = test_db
    app = create_app(TestConfig)
    app.config["DATABASE_PATH"] = test_db
    app.config["TESTING"] = True
    yield app

    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except Exception:
            pass


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_pcap_path():
    p = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "data", "sample_traffic.pcap")
    return os.path.abspath(p)


@pytest.fixture
def synthetic_packets():
    """Returns a deterministic list of test packets."""
    def eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=None):
        kw = {"src": src, "dst": dst}
        if type is not None:
            kw["type"] = type
        return Ether(**kw)

    p1 = eth() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=1000, dport=80, flags="S", seq=1)
    p1.time = 1700000000.0

    p2 = eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=2000, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.local"))
    p2.time = 1700000001.0

    p3 = eth() / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8, code=0)
    p3.time = 1700000002.0

    p4 = eth(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1")
    p4.time = 1700000003.0

    p5 = eth(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=0x86dd) / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=3000, dport=53)
    p5.time = 1700000004.0

    return [p1, p2, p3, p4, p5]
