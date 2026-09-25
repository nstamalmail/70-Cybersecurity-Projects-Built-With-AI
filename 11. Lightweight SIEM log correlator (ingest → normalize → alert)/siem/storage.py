"""SQLite persistence: events ring buffer, alerts, rules, meta.

Single connection + mutex so the processing thread (writes) and the GUI
thread (reads) can share it safely. All queries are parameterized.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional

from .events import Alert, NormalizedEvent
from .rules import DEFAULT_RULES, Rule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    source_type TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'INFO',
    message TEXT NOT NULL DEFAULT '',
    fields TEXT NOT NULL DEFAULT '{}',
    raw TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    group_key TEXT NOT NULL DEFAULT 'global',
    count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    fields TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rule_type TEXT NOT NULL DEFAULT 'regex',
    severity TEXT NOT NULL DEFAULT 'medium',
    enabled INTEGER NOT NULL DEFAULT 1,
    pattern TEXT NOT NULL DEFAULT '',
    field TEXT NOT NULL DEFAULT 'message',
    threshold INTEGER NOT NULL DEFAULT 5,
    window REAL NOT NULL DEFAULT 60,
    group_by TEXT NOT NULL DEFAULT '',
    cooldown REAL NOT NULL DEFAULT 60,
    steps TEXT NOT NULL DEFAULT '[]',
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, db_path: str, max_events_kept: int = 50000) -> None:
        self.db_path = db_path
        self.max_events_kept = max_events_kept
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(_SCHEMA)
            self.conn.commit()
            self._seed_rules()

    # ------------------------------------------------------------------ rules
    def _seed_rules(self) -> None:
        cur = self.conn.execute("SELECT COUNT(*) FROM rules")
        if cur.fetchone()[0] == 0:
            now = time.time()
            for d in DEFAULT_RULES:
                r = Rule.from_dict(d)
                self._insert_rule_row(r, now)
            self.conn.commit()

    def _insert_rule_row(self, r: Rule, now: float) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO rules (id, name, description, rule_type, severity,"
            " enabled, pattern, field, threshold, window, group_by, cooldown, steps, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r.id, r.name, r.description, r.rule_type, r.severity,
             1 if r.enabled else 0, r.pattern, r.field, r.threshold, r.window,
             r.group_by, r.cooldown, json.dumps(r.steps), now),
        )

    def get_rules(self) -> list[Rule]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM rules ORDER BY name").fetchall()
        return [Rule.from_dict(dict(row)) for row in rows]

    def save_rule(self, rule: Rule) -> None:
        with self._lock:
            self._insert_rule_row(rule, time.time())
            self.conn.commit()

    def delete_rule(self, rule_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
            self.conn.commit()

    def count_enabled_rules(self) -> int:
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()
        return int(row[0])

    # ----------------------------------------------------------------- events
    def insert_event(self, ev: NormalizedEvent) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO events (ts, source, source_type, host, severity, message, fields, raw)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (ev.ts, ev.source, ev.source_type, ev.host, ev.severity,
                 ev.message, json.dumps(ev.fields), ev.raw),
            )
            self._prune_events_locked()

    def _prune_events_locked(self) -> None:
        if self.max_events_kept <= 0:
            return
        row = self.conn.execute(
            "SELECT COUNT(*) - ? FROM events", (self.max_events_kept,)
        ).fetchone()
        overflow = int(row[0])
        if overflow > 100:  # prune in batches
            self.conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)",
                (overflow,),
            )

    def total_events(self) -> int:
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0])

    def events_since(self, since_ts: float) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts > ?", (since_ts,)
            ).fetchone()
        return int(row[0])

    # ----------------------------------------------------------------- alerts
    def insert_alert(self, alert: Alert) -> None:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO alerts (ts, rule_id, rule_name, severity, summary, group_key,"
                " count, status, fields) VALUES (?,?,?,?,?,?,?,?,?)",
                (alert.ts, alert.rule_id, alert.rule_name, alert.severity, alert.summary,
                 alert.group_key, alert.count, alert.status, json.dumps(alert.fields)),
            )
            self.conn.commit()
            alert.id = int(cur.lastrowid)

    def get_alerts(self, limit: int = 500, status: Optional[str] = None) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        with self._lock:
            rows = self.conn.execute(sql, params + (limit,)).fetchall()
        alerts = []
        for row in rows:
            alerts.append(Alert(
                id=int(row["id"]), ts=float(row["ts"]), rule_id=row["rule_id"],
                rule_name=row["rule_name"], severity=row["severity"],
                summary=row["summary"], group_key=row["group_key"],
                count=int(row["count"]), status=row["status"],
                fields=json.loads(row["fields"] or "{}"),
            ))
        return alerts

    def set_alert_status(self, alert_id: int, status: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
            self.conn.commit()

    def open_alert_count(self) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status='open'"
            ).fetchone()
        return int(row[0])

    def alerts_by_severity(self, since_ts: float) -> dict[str, int]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT severity, COUNT(*) AS c FROM alerts WHERE ts > ? GROUP BY severity",
                (since_ts,),
            ).fetchall()
        return {row["severity"]: int(row["c"]) for row in rows}

    # ------------------------------------------------------------------ misc
    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            open_alerts = int(
                self.conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            )
            enabled = int(
                self.conn.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0]
            )
            by_sev = {
                row["severity"]: int(row["c"])
                for row in self.conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM alerts WHERE ts > ? GROUP BY severity",
                    (time.time() - 86400,),
                ).fetchall()
            }
        return {"total_events": total, "open_alerts": open_alerts,
                "enabled_rules": enabled, "alerts_24h": by_sev}

    def close(self) -> None:
        with self._lock:
            self.conn.close()