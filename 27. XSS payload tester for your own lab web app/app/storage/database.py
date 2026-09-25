"""SQLite persistence: scans and findings for XPT."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import XssFinding, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    config_json TEXT,
    parameters_tested INTEGER DEFAULT 0,
    payloads_used INTEGER DEFAULT 0,
    total_requests INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    csp_present INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    url TEXT, method TEXT,
    parameter_name TEXT, parameter_location TEXT,
    xss_type TEXT, context TEXT, payload TEXT,
    encoded_in_response INTEGER, encoding_applied TEXT,
    browser_confirmed INTEGER, confirmation_method TEXT,
    severity TEXT, confidence TEXT, csp_present INTEGER,
    signal TEXT, reflection_snippet TEXT, request TEXT,
    response_snippet TEXT, remediation TEXT, references_json TEXT,
    status INTEGER, resp_time_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_xpt_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_xpt_findings_sev ON findings(severity);
"""


class Database:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(get_data_dir(), "xpt.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def create_scan(self, cfg: Any, target: str, csp_present: bool = False) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, target, config_json, csp_present) VALUES (?,?,?,?)",
                (now_iso(), target,
                 json.dumps(cfg.to_dict() if hasattr(cfg, "to_dict") else dict(cfg), default=str),
                 1 if csp_present else 0),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, params: int, payloads: int,
                    total_requests: int, findings: int, errors: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, parameters_tested=?, payloads_used=?, "
                "total_requests=?, findings_count=?, errors=? WHERE id=?",
                (now_iso(), params, payloads, total_requests, findings, errors, scan_id),
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

    def insert_finding(self, scan_id: int, f: XssFinding) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (scan_id, ts, url, method, parameter_name, parameter_location,
                    xss_type, context, payload, encoded_in_response, encoding_applied,
                    browser_confirmed, confirmation_method, severity, confidence,
                    csp_present, signal, reflection_snippet, request,
                    response_snippet, remediation, references_json, status, resp_time_ms)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, now_iso(), f.url, f.method, f.parameter_name,
                 f.parameter_location, f.xss_type, f.context, f.payload,
                 1 if f.encoded_in_response else 0, f.encoding_applied,
                 1 if f.browser_confirmed else 0, f.confirmation_method,
                 f.severity, f.confidence, 1 if f.csp_present else 0,
                 f.signal, f.reflection_snippet, f.request, f.response_snippet,
                 f.remediation, json.dumps(f.references), f.status, f.resp_time_ms),
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
            d["encoded_in_response"] = bool(d.get("encoded_in_response"))
            d["browser_confirmed"] = bool(d.get("browser_confirmed"))
            d["csp_present"] = bool(d.get("csp_present"))
            try:
                d["references"] = json.loads(d.get("references_json") or "[]")
            except Exception:
                d["references"] = []
            out.append(d)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
