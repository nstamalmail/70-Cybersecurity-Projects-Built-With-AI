"""SQLite persistence: challenges and operation records for RECT."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from app.config import get_data_dir
from app.core.models import Challenge, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT,
    name TEXT NOT NULL,
    category TEXT,
    event TEXT,
    description TEXT,
    flag_format TEXT,
    binary_path TEXT,
    solved INTEGER DEFAULT 0,
    flag TEXT,
    notes_md TEXT
);
CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER NOT NULL,
    ts TEXT,
    tool TEXT,
    operation TEXT,
    input_summary TEXT,
    output_summary TEXT,
    full_output TEXT,
    success INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rect_ops_ch ON operations(challenge_id);
"""


class Database:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(get_data_dir(), "rect.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------- challenges
    def create_challenge(self, ch: Challenge) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO challenges (created_at, name, category, event, "
                "description, flag_format, binary_path, solved, flag, notes_md) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (now_iso(), ch.name, ch.category, ch.event, ch.description,
                 ch.flag_format, ch.binary_path, 1 if ch.solved else 0,
                 ch.flag, ch.notes_md))
            self._conn.commit()
            return int(cur.lastrowid)

    def update_challenge(self, ch: Challenge) -> None:
        if ch.id is None:
            return
        with self._lock:
            self._conn.execute(
                "UPDATE challenges SET name=?, category=?, event=?, description=?, "
                "flag_format=?, binary_path=?, solved=?, flag=?, notes_md=? WHERE id=?",
                (ch.name, ch.category, ch.event, ch.description, ch.flag_format,
                 ch.binary_path, 1 if ch.solved else 0, ch.flag, ch.notes_md, ch.id))
            self._conn.commit()

    def list_challenges(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM challenges ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["solved"] = bool(d.get("solved"))
            out.append(d)
        return out

    def get_challenge(self, cid: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["solved"] = bool(d.get("solved"))
        return d

    def delete_challenge(self, cid: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM operations WHERE challenge_id=?", (cid,))
            self._conn.execute("DELETE FROM challenges WHERE id=?", (cid,))
            self._conn.commit()

    # -------------------------------------------------------------- operations
    def insert_operation(self, challenge_id: int, rec: Any) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO operations (challenge_id, ts, tool, operation, "
                "input_summary, output_summary, full_output, success) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (challenge_id, now_iso(), rec.tool, rec.operation,
                 rec.input_summary, rec.output_summary, rec.full_output,
                 1 if rec.success else 0))
            self._conn.commit()
            return int(cur.lastrowid)

    def list_operations(self, challenge_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM operations WHERE challenge_id=? ORDER BY id",
                (challenge_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["success"] = bool(d.get("success"))
            out.append(d)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
