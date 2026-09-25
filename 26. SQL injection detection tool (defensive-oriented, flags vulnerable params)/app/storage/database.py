"""SQLite persistence: scans and findings for SIDT."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import SqlInjectionFinding, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    config_json TEXT,
    parameters_tested INTEGER DEFAULT 0,
    total_requests INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    safe_mode INTEGER DEFAULT 1,
    waf TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    url TEXT, method TEXT,
    parameter_name TEXT, parameter_location TEXT,
    technique TEXT, confidence TEXT, severity TEXT,
    dbms_hint TEXT, signal TEXT, payload TEXT,
    baseline_request TEXT, injected_request TEXT,
    baseline_response_snippet TEXT, injected_response_snippet TEXT,
    response_delta TEXT, remediation TEXT, references_json TEXT,
    status INTEGER, resp_time_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_sdt_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_sdt_findings_sev ON findings(severity);
"""


class Database:
    """Thread-safe SQLite access layer (single connection, lock-guarded)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(get_data_dir(), "sidt.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ scans
    def create_scan(self, cfg: Any, target: str, safe_mode: bool = True) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, target, config_json, safe_mode) VALUES (?,?,?,?)",
                (now_iso(), target,
                 json.dumps(cfg.to_dict() if hasattr(cfg, "to_dict") else dict(cfg), default=str),
                 1 if safe_mode else 0),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, params: int, total_requests: int,
                    findings: int, errors: int, waf: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, parameters_tested=?, total_requests=?, "
                "findings_count=?, errors=?, waf=? WHERE id=?",
                (now_iso(), params, total_requests, findings, errors, waf, scan_id),
            )
            self._conn.commit()

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
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

    # --------------------------------------------------------------- findings
    def insert_finding(self, scan_id: int, f: SqlInjectionFinding) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (scan_id, ts, url, method, parameter_name, parameter_location,
                    technique, confidence, severity, dbms_hint, signal, payload,
                    baseline_request, injected_request, baseline_response_snippet,
                    injected_response_snippet, response_delta, remediation,
                    references_json, status, resp_time_ms)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, now_iso(), f.url, f.method, f.parameter_name,
                 f.parameter_location, f.technique, f.confidence, f.severity,
                 f.dbms_hint, f.signal, f.payload, f.baseline_request,
                 f.injected_request, f.baseline_response_snippet,
                 f.injected_response_snippet,
                 json.dumps(f.response_delta, default=str), f.remediation,
                 json.dumps(f.references), f.status, f.resp_time_ms),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def list_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["response_delta"] = json.loads(d.get("response_delta") or "{}")
            except Exception:
                d["response_delta"] = {}
            try:
                d["references"] = json.loads(d.get("references_json") or "[]")
            except Exception:
                d["references"] = []
            out.append(d)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
