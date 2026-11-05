"""
NetScope SQLite Storage Module
Persists session metadata, statistical summaries, and security alert history using parameterized queries.
Does not store massive raw packet payloads permanently, preserving storage efficiency.
"""

import sqlite3
import os
import json
from contextlib import contextmanager
from datetime import datetime, timezone


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

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
                    classification_nature TEXT,
                    severity TEXT,
                    timestamp REAL,
                    host TEXT,
                    observed_metric TEXT,
                    configured_threshold TEXT,
                    explanation TEXT,
                    packet_references TEXT,
                    created_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    capture_id TEXT,
                    category TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    severity_rationale TEXT,
                    status TEXT DEFAULT 'New',
                    first_seen REAL,
                    last_seen REAL,
                    source_host TEXT,
                    target_host TEXT,
                    observed_value TEXT,
                    configured_threshold TEXT,
                    observation_window TEXT,
                    explanation TEXT,
                    benign_explanation TEXT,
                    evidence_json TEXT,
                    analyst_notes TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT,
                    priority TEXT DEFAULT 'Medium',
                    status TEXT DEFAULT 'Open',
                    analyst TEXT DEFAULT 'SecOps Analyst',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    author TEXT DEFAULT 'SecOps Analyst',
                    note TEXT NOT NULL,
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases (case_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases (case_id)
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
        refs_json = json.dumps(alert.get("packet_references", []))
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (alert_id, capture_id, alert_type, classification_nature, severity, timestamp, host, observed_metric, configured_threshold, explanation, packet_references, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("alert_id"),
                capture_id,
                alert.get("alert_type"),
                alert.get("classification_nature", "Heuristic"),
                alert.get("severity"),
                alert.get("timestamp", 0.0),
                alert.get("host"),
                alert.get("observed_value") or alert.get("observed_metric"),
                alert.get("threshold") or alert.get("configured_threshold"),
                alert.get("explanation"),
                refs_json,
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
            rows = cursor.fetchall()
            alerts = []
            for row in rows:
                item = dict(row)
                item["observed_value"] = item.get("observed_metric") or item.get("observed_value") or "Not applicable"
                item["threshold"] = item.get("configured_threshold") or item.get("threshold") or "Not specified"
                try:
                    item["packet_references"] = json.loads(item.get("packet_references") or "[]")
                except Exception:
                    item["packet_references"] = []
                alerts.append(item)
            return alerts

    # -------------------------------------------------------------
    # INCIDENTS (Correlated Security Intelligence)
    # -------------------------------------------------------------

    def upsert_incident(self, incident: dict) -> dict:
        """Inserts or updates a correlated security incident."""
        now = datetime.now(timezone.utc).isoformat()
        evidence_json = json.dumps(incident.get("evidence", {}))
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT incident_id, status, analyst_notes, created_at FROM incidents WHERE incident_id = ?", (incident["incident_id"],))
            existing = cursor.fetchone()

            if existing:
                status = incident.get("status") or existing["status"]
                notes = incident.get("analyst_notes") if "analyst_notes" in incident else existing["analyst_notes"]
                created_at = existing["created_at"]
                cursor.execute("""
                    UPDATE incidents SET
                        capture_id = ?, category = ?, rule_name = ?, severity = ?, severity_rationale = ?,
                        status = ?, first_seen = ?, last_seen = ?, source_host = ?, target_host = ?,
                        observed_value = ?, configured_threshold = ?, observation_window = ?,
                        explanation = ?, benign_explanation = ?, evidence_json = ?, analyst_notes = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                """, (
                    incident.get("capture_id"),
                    incident.get("category", "ANOMALY"),
                    incident.get("rule_name", "Security Rule"),
                    incident.get("severity", "MEDIUM"),
                    incident.get("severity_rationale", ""),
                    status,
                    incident.get("first_seen", 0.0),
                    incident.get("last_seen", 0.0),
                    incident.get("source_host", "Unknown"),
                    incident.get("target_host", "Unknown"),
                    incident.get("observed_value", ""),
                    incident.get("configured_threshold", ""),
                    incident.get("observation_window", ""),
                    incident.get("explanation", ""),
                    incident.get("benign_explanation", ""),
                    evidence_json,
                    notes,
                    now,
                    incident["incident_id"]
                ))
            else:
                cursor.execute("""
                    INSERT INTO incidents (
                        incident_id, capture_id, category, rule_name, severity, severity_rationale,
                        status, first_seen, last_seen, source_host, target_host,
                        observed_value, configured_threshold, observation_window,
                        explanation, benign_explanation, evidence_json, analyst_notes,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident["incident_id"],
                    incident.get("capture_id"),
                    incident.get("category", "ANOMALY"),
                    incident.get("rule_name", "Security Rule"),
                    incident.get("severity", "MEDIUM"),
                    incident.get("severity_rationale", ""),
                    incident.get("status", "New"),
                    incident.get("first_seen", 0.0),
                    incident.get("last_seen", 0.0),
                    incident.get("source_host", "Unknown"),
                    incident.get("target_host", "Unknown"),
                    incident.get("observed_value", ""),
                    incident.get("configured_threshold", ""),
                    incident.get("observation_window", ""),
                    incident.get("explanation", ""),
                    incident.get("benign_explanation", ""),
                    evidence_json,
                    incident.get("analyst_notes", ""),
                    now,
                    now
                ))
            conn.commit()
        return self.get_incident(incident["incident_id"])

    def update_incident_status(self, incident_id: str, status: str, notes: str = None) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if notes is not None:
                cursor.execute("UPDATE incidents SET status = ?, analyst_notes = ?, updated_at = ? WHERE incident_id = ?",
                               (status, notes, now, incident_id))
            else:
                cursor.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                               (status, now, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_incident(self, incident_id: str) -> dict | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["evidence"] = json.loads(item.get("evidence_json") or "{}")
            except Exception:
                item["evidence"] = {}
            return item

    def get_incidents(self, capture_id: str = None, status: str = None, severity: str = None, limit: int = 100) -> list[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM incidents WHERE 1=1"
            params = []
            if capture_id:
                query += " AND capture_id = ?"
                params.append(capture_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY last_seen DESC, rowid DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["evidence"] = json.loads(item.get("evidence_json") or "{}")
                except Exception:
                    item["evidence"] = {}
                results.append(item)
            return results

    # -------------------------------------------------------------
    # CASES & WORKBENCH INVESTIGATIONS
    # -------------------------------------------------------------

    def create_case(self, case_id: str, title: str, summary: str = "", priority: str = "Medium", status: str = "Open", analyst: str = "SecOps Analyst") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cases (case_id, title, summary, priority, status, analyst, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (case_id, title, summary, priority, status, analyst, now, now))
            conn.commit()
        return self.get_case(case_id)

    def update_case(self, case_id: str, updates: dict) -> dict | None:
        now = datetime.now(timezone.utc).isoformat()
        allowed = {"title", "summary", "priority", "status", "analyst"}
        set_clauses = []
        params = []
        for k, v in updates.items():
            if k in allowed:
                set_clauses.append(f"{k} = ?")
                params.append(v)
        if not set_clauses:
            return self.get_case(case_id)

        set_clauses.append("updated_at = ?")
        params.append(now)
        params.append(case_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE cases SET {', '.join(set_clauses)} WHERE case_id = ?", params)
            conn.commit()
        return self.get_case(case_id)

    def add_case_note(self, case_id: str, note: str, author: str = "SecOps Analyst") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (case_id, author, note, now))
            # Also update case updated_at
            cursor.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
            note_id = cursor.lastrowid
            conn.commit()
        return {"id": note_id, "case_id": case_id, "author": author, "note": note, "created_at": now}

    def attach_case_artifact(self, case_id: str, artifact_type: str, artifact_id: str, metadata: dict = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {})
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Prevent exact duplicate artifact attachment
            cursor.execute("SELECT id FROM case_artifacts WHERE case_id = ? AND artifact_type = ? AND artifact_id = ?",
                           (case_id, artifact_type, str(artifact_id)))
            row = cursor.fetchone()
            if row:
                art_id = row["id"]
            else:
                cursor.execute("""
                    INSERT INTO case_artifacts (case_id, artifact_type, artifact_id, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (case_id, artifact_type, str(artifact_id), meta_json, now))
                art_id = cursor.lastrowid
                cursor.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
                conn.commit()
        return {
            "id": art_id,
            "case_id": case_id,
            "artifact_type": artifact_type,
            "artifact_id": str(artifact_id),
            "metadata": metadata or {},
            "created_at": now
        }

    def get_case(self, case_id: str) -> dict | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            case_row = cursor.fetchone()
            if not case_row:
                return None
            case_data = dict(case_row)

            cursor.execute("SELECT * FROM case_notes WHERE case_id = ? ORDER BY id ASC", (case_id,))
            case_data["notes"] = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT * FROM case_artifacts WHERE case_id = ? ORDER BY id ASC", (case_id,))
            artifacts = []
            for r in cursor.fetchall():
                art = dict(r)
                try:
                    art["metadata"] = json.loads(art.get("metadata_json") or "{}")
                except Exception:
                    art["metadata"] = {}
                artifacts.append(art)
            case_data["artifacts"] = artifacts
            return case_data

    def get_cases(self, limit: int = 50) -> list[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,))
            cases = [dict(r) for r in cursor.fetchall()]
            for c in cases:
                cursor.execute("SELECT COUNT(*) as count FROM case_notes WHERE case_id = ?", (c["case_id"],))
                c["notes_count"] = cursor.fetchone()["count"]
                cursor.execute("SELECT COUNT(*) as count FROM case_artifacts WHERE case_id = ?", (c["case_id"],))
                c["artifacts_count"] = cursor.fetchone()["count"]
            return cases
