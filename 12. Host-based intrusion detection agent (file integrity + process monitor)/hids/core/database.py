"""SQLite storage: baseline, alerts, scans, meta.

Thread-safety: one connection per thread (thread-local), WAL journal mode, so
GUI / FIM engine / process engine can touch the DB concurrently.
"""

import hashlib
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .models import Alert, FileRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    path       TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    mtime      REAL    NOT NULL,
    sha256     TEXT    NOT NULL,
    first_seen REAL    NOT NULL,
    last_seen  REAL    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_baseline_sha ON baseline(sha256);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    REAL    NOT NULL,
    severity     TEXT    NOT NULL,
    category     TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    details      TEXT    NOT NULL DEFAULT '{}',
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started       REAL,
    finished      REAL,
    files_scanned INTEGER DEFAULT 0,
    modified      INTEGER DEFAULT 0,
    added         INTEGER DEFAULT 0,
    deleted       INTEGER DEFAULT 0,
    errors        INTEGER DEFAULT 0,
    duration      REAL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    def __init__(self, data_dir: Path):
        self.db_path = Path(data_dir) / "hids.db"
        self._local = threading.local()
        self._init_schema()

    # -- plumbing ---------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    @contextmanager
    def _tx(self):
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self) -> None:
        with self._tx() as conn:
            conn.executescript(_SCHEMA)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- baseline ---------------------------------------------------------
    def replace_baseline(self, records) -> None:
        now = time.time()
        with self._tx() as conn:
            conn.execute("DELETE FROM baseline")
            conn.executemany(
                "INSERT INTO baseline(path,size,mtime,sha256,first_seen,last_seen)"
                " VALUES(?,?,?,?,?,?)",
                [
                    (r.path, r.size, r.mtime, r.sha256, now, now)
                    for r in records
                ],
            )

    def upsert_baseline(self, records) -> None:
        if not records:
            return
        now = time.time()
        with self._tx() as conn:
            conn.executemany(
                "INSERT INTO baseline(path,size,mtime,sha256,first_seen,last_seen)"
                " VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(path) DO UPDATE SET size=excluded.size,"
                " mtime=excluded.mtime, sha256=excluded.sha256,"
                " last_seen=excluded.last_seen, status='ok'",
                [(r.path, r.size, r.mtime, r.sha256, now, now) for r in records],
            )

    def remove_baseline(self, paths) -> None:
        if not paths:
            return
        with self._tx() as conn:
            conn.executemany(
                "DELETE FROM baseline WHERE path=?", [(p,) for p in paths]
            )

    def all_baseline(self):
        with self._tx() as conn:
            return conn.execute("SELECT * FROM baseline ORDER BY path").fetchall()

    def get_baseline_row(self, path: str):
        with self._tx() as conn:
            return conn.execute(
                "SELECT * FROM baseline WHERE path=?", (path,)
            ).fetchone()

    def baseline_count(self) -> int:
        with self._tx() as conn:
            return conn.execute("SELECT COUNT(*) AS c FROM baseline").fetchone()["c"]

    def baseline_fingerprint(self) -> str:
        """SHA-256 over all baseline rows — detects baseline DB tampering."""
        sha = hashlib.sha256()
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT path,size,mtime,sha256 FROM baseline ORDER BY path"
            ).fetchall()
        for r in rows:
            sha.update(f"{r['path']}|{r['size']}|{r['mtime']}|{r['sha256']}\n".encode("utf-8", "replace"))
        return sha.hexdigest()

    # -- alerts -----------------------------------------------------------
    def add_alert(self, alert: Alert) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO alerts(timestamp,severity,category,event_type,title,details,acknowledged)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    alert.timestamp,
                    alert.severity,
                    alert.category,
                    alert.event_type,
                    alert.title,
                    alert.details_json(),
                    int(alert.acknowledged),
                ),
            )
            alert.id = cur.lastrowid
            return alert.id

    def alerts(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 1000,
    ):
        q = "SELECT * FROM alerts WHERE 1=1"
        args: list = []
        if severity and severity != "All":
            q += " AND severity=?"
            args.append(severity)
        if category and category != "All":
            q += " AND category=?"
            args.append(category)
        if search:
            q += " AND (title LIKE ? OR details LIKE ? OR event_type LIKE ?)"
            like = f"%{search}%"
            args += [like, like, like]
        q += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._tx() as conn:
            rows = conn.execute(q, args).fetchall()
        return [Alert.from_row(r) for r in rows]

    def set_acknowledged(self, alert_id: int, ack: int = 1) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged=? WHERE id=?", (int(ack), alert_id)
            )

    def delete_alerts(self, alert_ids) -> None:
        if not alert_ids:
            return
        with self._tx() as conn:
            conn.executemany(
                "DELETE FROM alerts WHERE id=?", [(i,) for i in alert_ids]
            )

    def clear_alerts(self) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM alerts")

    def prune_alerts(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            return cur.rowcount

    def alert_counts(self) -> dict:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
            ).fetchall()
        counts = {r["severity"]: r["c"] for r in rows}
        counts["TOTAL"] = sum(counts.values())
        return counts

    # -- scans ------------------------------------------------------------
    def start_scan(self) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO scans(started) VALUES(?)", (time.time(),)
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, stats: dict) -> None:
        finished = time.time()
        with self._tx() as conn:
            conn.execute(
                "UPDATE scans SET finished=?, files_scanned=?, modified=?,"
                " added=?, deleted=?, errors=?, duration=? WHERE id=?",
                (
                    finished,
                    stats.get("files_scanned", 0),
                    stats.get("modified", 0),
                    stats.get("added", 0),
                    stats.get("deleted", 0),
                    stats.get("errors", 0),
                    finished - stats.get("started", finished),
                    scan_id,
                ),
            )

    def last_scan(self):
        with self._tx() as conn:
            return conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()

    # -- meta -------------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)
            ).fetchone()
        return row["value"] if row else default
