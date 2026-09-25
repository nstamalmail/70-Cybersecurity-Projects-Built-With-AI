"""SQLite persistence: scans and findings."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import Finding, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    config_json TEXT,
    total_requests INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    category TEXT,
    technique TEXT,
    severity TEXT,
    injection_kind TEXT,
    injection_name TEXT,
    payload TEXT,
    encoding TEXT,
    url TEXT,
    status INTEGER,
    resp_len INTEGER,
    resp_time_ms REAL,
    evidence TEXT,
    request TEXT,
    response TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class Database:
    """Thread-safe SQLite access layer (single connection, guarded by lock)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or __import__("os").path.join(get_data_dir(), "webfuzzer.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ scans
    def create_scan(self, config: Any, target: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, target, config_json) VALUES (?, ?, ?)",
                (now_iso(), target, json.dumps(config.to_dict() if hasattr(config, "to_dict") else config, default=str)),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, total_requests: int, findings: int, errors: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, total_requests=?, findings_count=?, errors=? WHERE id=?",
                (now_iso(), total_requests, findings, errors, scan_id),
            )
            self._conn.commit()

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def delete_scan(self, scan_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            self._conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            self._conn.commit()

    def clear_all(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings")
            self._conn.execute("DELETE FROM scans")
            self._conn.commit()

    # --------------------------------------------------------------- findings
    def insert_finding(self, scan_id: int, f: Finding) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (scan_id, ts, category, technique, severity, injection_kind,
                    injection_name, payload, encoding, url, status, resp_len,
                    resp_time_ms, evidence, request, response)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, now_iso(), f.category, f.technique, f.severity,
                 f.injection_kind, f.injection_name, f.payload, f.encoding,
                 f.url, f.status, f.resp_len, f.resp_time_ms, f.evidence,
                 f.request, f.response),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def list_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def findings_summary(self, scan_id: int) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id=? GROUP BY severity",
                (scan_id,),
            ).fetchall()
        return {r["severity"]: r["n"] for r in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()