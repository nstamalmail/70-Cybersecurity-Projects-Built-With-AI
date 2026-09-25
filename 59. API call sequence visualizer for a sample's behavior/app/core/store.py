"""SQLite persistence for analysed reports (architecture §3.10).

Every run is written to ``<data>/cases.db`` so an analyst can pivot across
samples without keeping the original reports around:

``runs``      one row per analysis (sample, format, score, verdict, counts)
``calls``     the normalised call stream (optionally capped for huge reports)
``findings``  behavioural pattern hits
``indicators`` extracted IOCs

The store is deliberately append-only and idempotent per run id, and it degrades
to a no-op if SQLite is unavailable or the database is locked.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import case_db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    created_at   TEXT,
    sample_name  TEXT,
    sha256       TEXT,
    source       TEXT,
    source_format TEXT,
    duration     REAL,
    call_count   INTEGER,
    process_count INTEGER,
    finding_count INTEGER,
    ioc_count    INTEGER,
    score        INTEGER,
    severity     TEXT
);
CREATE TABLE IF NOT EXISTS calls (
    run_id     TEXT,
    call_id    TEXT,
    timestamp  REAL,
    process_id INTEGER,
    process_name TEXT,
    category   TEXT,
    api        TEXT,
    status     TEXT,
    repeated   INTEGER,
    arguments  TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    run_id      TEXT,
    pattern_id  TEXT,
    name        TEXT,
    severity    TEXT,
    process_id  INTEGER,
    process_name TEXT,
    start_ts    REAL,
    end_ts      REAL,
    apis        TEXT,
    target      TEXT
);
CREATE TABLE IF NOT EXISTS indicators (
    run_id     TEXT,
    ioc_type   TEXT,
    value      TEXT,
    source     TEXT,
    confidence REAL,
    context    TEXT
);
CREATE INDEX IF NOT EXISTS idx_calls_run ON calls(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
"""


class CaseStore:
    """Thin SQLite wrapper used by the engine and the Tools menu."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else case_db_path()
        self.available = True
        self.error = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.executescript(SCHEMA)
        except Exception as exc:
            self.available = False
            self.error = str(exc)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    # ------------------------------------------------------------------ write
    def store_run(self, result, *, max_calls: int = 50_000) -> bool:
        if not self.available:
            return False
        try:
            with self._connect() as connection:
                run_id = result.meta.report_id or result.source_name or "run"
                connection.execute(
                    """
                    INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        run_id,
                        result.meta.parsed_at,
                        result.meta.sample_name or result.source_name,
                        result.meta.sample_sha256,
                        result.source_path,
                        result.source_format,
                        result.duration,
                        result.call_count,
                        len(result.processes),
                        len(result.matches),
                        len(result.iocs),
                        result.score,
                        result.severity,
                    ),
                )
                connection.execute("DELETE FROM calls WHERE run_id = ?", (run_id,))
                connection.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
                connection.execute("DELETE FROM indicators WHERE run_id = ?", (run_id,))
                connection.executemany(
                    "INSERT INTO calls VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            run_id,
                            call.call_id,
                            call.timestamp,
                            call.process_id,
                            call.process_name,
                            call.category,
                            call.api,
                            call.status,
                            call.repeated,
                            call.arguments_text[:400],
                        )
                        for call in result.calls[:max_calls]
                    ],
                )
                connection.executemany(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            run_id,
                            match.pattern_id,
                            match.name,
                            match.severity,
                            match.process_id,
                            match.process_name,
                            match.start_ts,
                            match.end_ts,
                            " -> ".join(match.apis),
                            match.target,
                        )
                        for match in result.matches
                    ],
                )
                connection.executemany(
                    "INSERT INTO indicators VALUES (?,?,?,?,?,?)",
                    [
                        (
                            run_id,
                            item["type"],
                            item["value"],
                            item.get("source", ""),
                            float(item.get("confidence", 0.0)),
                            item.get("context", ""),
                        )
                        for item in result.iocs
                    ],
                )
            return True
        except Exception as exc:  # pragma: no cover - storage must never break a run
            self.error = str(exc)
            return False

    # ------------------------------------------------------------------- read
    def runs(self, limit: int = 200) -> list[dict]:
        if not self.available:
            return []
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def calls(self, run_id: str, limit: int = 5000) -> list[dict]:
        if not self.available:
            return []
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM calls WHERE run_id = ? ORDER BY timestamp LIMIT ?",
                    (run_id, limit),
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def indicators(self, limit: int = 5000) -> list[dict]:
        if not self.available:
            return []
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM indicators ORDER BY confidence DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def counts(self) -> dict[str, int]:
        if not self.available:
            return {}
        try:
            with self._connect() as connection:
                return {
                    table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("runs", "calls", "findings", "indicators")
                }
        except Exception:
            return {}
