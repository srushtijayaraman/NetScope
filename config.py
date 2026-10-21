import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("NETSCOPE_SECRET_KEY", "netscope-academic-secret-key-2026")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "data", "uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB upload limit
    ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
    
    # Storage
    DATABASE_PATH = os.path.join(BASE_DIR, "storage", "netscope.db")
    
    # Processing & Memory limits
    MAX_MEMORY_PACKETS = 10000  # Detailed packet explorer ring buffer limit
    CAPTURE_QUEUE_SIZE = 5000   # Bounded queue for live capture
    
    # Anomaly Detection Defaults
    PACKET_RATE_THRESHOLD = 150       # packets/sec in a 1-second window
    BYTE_RATE_THRESHOLD = 500_000     # bytes/sec (4 Mbps)
    SYN_FLOOD_THRESHOLD = 20          # SYNs from single IP in 5-sec window
    PORT_SCAN_THRESHOLD = 15          # Distinct destination ports scanned in 5-sec window
    HOST_VOLUME_RATIO_THRESHOLD = 0.5 # Single IP sending > 50% of traffic (min 50 packets)
    ANOMALY_COOLDOWN_SECONDS = 10     # Cooldown between duplicate alerts

import tempfile

class TestConfig(Config):
    TESTING = True
    DATABASE_PATH = os.path.join(tempfile.gettempdir(), "netscope_test.db")
    MAX_MEMORY_PACKETS = 500
    CAPTURE_QUEUE_SIZE = 100
