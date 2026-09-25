"""SQLite persistence: audits and targets for WNA."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import WirelessAudit, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    audit_id TEXT,
    adapter TEXT,
    monitor_interface TEXT,
    allowlist_json TEXT,
    capture_method TEXT,
    notes TEXT,
    targets_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL,
    bssid TEXT, essid TEXT, channel INTEGER, encryption TEXT,
    handshake_captured INTEGER, handshake_completeness TEXT,
    messages_json TEXT, pmkid_captured INTEGER,
    hash_file TEXT,
    crack_attempted INTEGER, crack_tool TEXT, crack_result TEXT,
    crack_duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_wna_targets_audit ON targets(audit_id);
"""


class Database:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(get_data_dir(), "wna.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def create_audit(self, audit: WirelessAudit) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO audits (started_at, audit_id, adapter, "
                "monitor_interface, allowlist_json, capture_method, notes) "
                "VALUES (?,?,?,?,?,?,?)",
                (now_iso(), audit.audit_id, audit.adapter,
                 audit.monitor_interface, json.dumps(audit.allowlist),
                 audit.capture_method, audit.notes))
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_audit(self, audit_id: int, targets: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE audits SET finished_at=?, targets_count=? WHERE id=?",
                (now_iso(), targets, audit_id))
            self._conn.commit()

    def insert_target(self, audit_db_id: int, t: Any) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO targets
                   (audit_id, bssid, essid, channel, encryption,
                    handshake_captured, handshake_completeness, messages_json,
                    pmkid_captured, hash_file, crack_attempted, crack_tool,
                    crack_result, crack_duration_seconds)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (audit_db_id, t.bssid, t.essid, t.channel, t.encryption,
                 1 if t.handshake_captured else 0, t.handshake_completeness,
                 json.dumps(t.messages_present),
                 1 if t.pmkid_captured else 0, t.hash_file,
                 1 if t.crack_attempted else 0, t.crack_tool, t.crack_result,
                 t.crack_duration_seconds))
            self._conn.commit()
            return int(cur.lastrowid)

    def list_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audits ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_audit(self, audit_db_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audits WHERE id=?", (audit_db_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["allowlist"] = json.loads(d.get("allowlist_json") or "[]")
        except Exception:
            d["allowlist"] = []
        return d

    def list_targets(self, audit_db_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM targets WHERE audit_id=? ORDER BY id",
                (audit_db_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["handshake_captured"] = bool(d.get("handshake_captured"))
            d["pmkid_captured"] = bool(d.get("pmkid_captured"))
            d["crack_attempted"] = bool(d.get("crack_attempted"))
            try:
                d["messages_present"] = json.loads(d.get("messages_json") or "[]")
            except Exception:
                d["messages_present"] = []
            out.append(d)
        return out

    def delete_audit(self, audit_db_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM targets WHERE audit_id=?", (audit_db_id,))
            self._conn.execute("DELETE FROM audits WHERE id=?", (audit_db_id,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
