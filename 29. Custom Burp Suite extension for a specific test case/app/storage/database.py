"""SQLite persistence: sessions and findings for CBSEF."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import CandidateFinding, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    name TEXT,
    test_case TEXT,
    config_json TEXT,
    findings_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    finding_id TEXT,
    test_case TEXT,
    url TEXT, method TEXT, endpoint TEXT, parameter TEXT,
    confidence TEXT, status TEXT,
    signal_description TEXT,
    baseline_request TEXT, baseline_response TEXT,
    probe_request TEXT, probe_response TEXT,
    differential TEXT, remediation TEXT
);
CREATE INDEX IF NOT EXISTS idx_cbsef_findings_session ON findings(session_id);
"""


class Database:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(get_data_dir(), "cbsef.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ----------------------------------------------------------------- sessions
    def create_session(self, name: str, test_case: str, config: Any = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO sessions (started_at, name, test_case, config_json) "
                "VALUES (?,?,?,?)",
                (now_iso(), name, test_case,
                 json.dumps(config if isinstance(config, dict) else {},
                            default=str)))
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_session(self, session_id: int, findings: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET finished_at=?, findings_count=? WHERE id=?",
                (now_iso(), findings, session_id))
            self._conn.commit()

    def list_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def delete_session(self, session_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings WHERE session_id=?", (session_id,))
            self._conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
            self._conn.commit()

    # ----------------------------------------------------------------- findings
    def insert_finding(self, session_id: int, f: CandidateFinding) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (session_id, ts, finding_id, test_case, url, method, endpoint,
                    parameter, confidence, status, signal_description,
                    baseline_request, baseline_response, probe_request,
                    probe_response, differential, remediation)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, now_iso(), f.finding_id, f.test_case, f.url,
                 f.method, f.endpoint, f.parameter, f.confidence, f.status,
                 f.signal_description, f.baseline_request, f.baseline_response,
                 f.probe_request, f.probe_response,
                 json.dumps(f.differential, default=str), f.remediation))
            self._conn.commit()
            return int(cur.lastrowid)

    def set_status(self, finding_db_id: int, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE findings SET status=? WHERE id=?",
                               (status, finding_db_id))
            self._conn.commit()

    def list_findings(self, session_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY id",
                (session_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["differential"] = json.loads(d.get("differential") or "{}")
            except Exception:
                d["differential"] = {}
            out.append(d)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
