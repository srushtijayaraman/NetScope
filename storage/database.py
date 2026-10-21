"""
NetScope SQLite Storage Module
Persists session metadata, statistical summaries, and security alert history using parameterized queries.
Does not store massive raw packet payloads permanently, preserving storage efficiency.
"""

import sqlite3
import os
import json
from datetime import datetime, timezone


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes tables for sessions, summaries, and alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    capture_id TEXT PRIMARY KEY,
                    filename TEXT,
                    mode TEXT,
                    packet_count INTEGER DEFAULT 0,
                    byte_count INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0.0,
                    created_at TEXT,
                    status TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_summaries (
                    capture_id TEXT PRIMARY KEY,
                    summary_json TEXT,
                    updated_at TEXT,
                    FOREIGN KEY (capture_id) REFERENCES sessions (capture_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT,
                    capture_id TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    timestamp REAL,
                    host TEXT,
                    observed_metric TEXT,
                    configured_threshold TEXT,
                    explanation TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()

    def record_session(self, capture_id: str, filename: str, mode: str, packet_count: int, byte_count: int, duration_seconds: float, status: str = "COMPLETED"):
        """Saves or updates capture session metadata."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO sessions (capture_id, filename, mode, packet_count, byte_count, duration_seconds, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (capture_id, filename, mode, packet_count, byte_count, duration_seconds, now, status))
            conn.commit()

    def save_summary(self, capture_id: str, summary_data: dict):
        """Stores structured JSON summary for quick retrieval."""
        now = datetime.now(timezone.utc).isoformat()
        json_str = json.dumps(summary_data)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO session_summaries (capture_id, summary_json, updated_at)
                VALUES (?, ?, ?)
            """, (capture_id, json_str, now))
            conn.commit()

    def save_alert(self, capture_id: str, alert: dict):
        """Appends an alert to historical records."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (alert_id, capture_id, alert_type, severity, timestamp, host, observed_metric, configured_threshold, explanation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("alert_id"),
                capture_id,
                alert.get("alert_type"),
                alert.get("severity"),
                alert.get("timestamp", 0.0),
                alert.get("host"),
                alert.get("observed_metric"),
                alert.get("configured_threshold"),
                alert.get("explanation"),
                now,
            ))
            conn.commit()

    def get_sessions(self, limit: int = 50) -> list[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_alerts(self, capture_id: str = None, limit: int = 100) -> list[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if capture_id:
                cursor.execute("SELECT * FROM alerts WHERE capture_id = ? ORDER BY id DESC LIMIT ?", (capture_id, limit))
            else:
                cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
