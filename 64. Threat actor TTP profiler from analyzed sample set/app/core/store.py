"""SQLite persistence for analysed reports."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import case_db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, created_at TEXT, sample_name TEXT, sha256 TEXT,
    source TEXT, source_format TEXT, call_count INTEGER, process_count INTEGER,
    persistence_count INTEGER, ioc_count INTEGER, score INTEGER, severity TEXT
);
CREATE TABLE IF NOT EXISTS persistence (
    run_id TEXT, technique_id TEXT, technique_name TEXT, severity TEXT,
    source TEXT, evidence TEXT, confidence REAL, key_path TEXT, service_name TEXT
);
CREATE TABLE IF NOT EXISTS indicators (
    run_id TEXT, ioc_type TEXT, value TEXT, source TEXT, confidence REAL, context TEXT
);
CREATE INDEX IF NOT EXISTS idx_persistence_run ON persistence(run_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
"""


class CaseStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else case_db_path()
        self.available = True
        self.error = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.executescript(SCHEMA)
        except Exception as exc:
            self.available = False
            self.error = str(exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def store_run(self, result, *, max_calls: int = 50_000) -> bool:
        if not self.available:
            return False
        try:
            with self._connect() as conn:
                run_id = result.meta.report_id or result.source_name or "run"
                conn.execute(
                    "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, result.meta.parsed_at, result.meta.sample_name or result.source_name,
                     result.meta.sample_sha256, result.source_path, result.source_format,
                     len(result.calls), len(result.processes), len(result.artifacts),
                     len(result.iocs), result.score, result.severity),
                )
                conn.execute("DELETE FROM persistence WHERE run_id = ?", (run_id,))
                conn.execute("DELETE FROM indicators WHERE run_id = ?", (run_id,))
                conn.executemany(
                    "INSERT INTO persistence VALUES (?,?,?,?,?,?,?,?,?)",
                    [(run_id, a.technique_id, a.technique_name, a.severity, a.source,
                      "; ".join(a.evidence), a.confidence, a.key_path, a.service_name)
                     for a in result.artifacts],
                )
                conn.executemany(
                    "INSERT INTO indicators VALUES (?,?,?,?,?,?)",
                    [(run_id, item.get("type",""), item.get("value",""), item.get("source",""),
                      float(item.get("confidence", 0.0)), item.get("context",""))
                     for item in result.iocs],
                )
            return True
        except Exception as exc:
            self.error = str(exc)
            return False

    def runs(self, limit: int = 200) -> list[dict]:
        if not self.available:
            return []
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def counts(self) -> dict[str, int]:
        if not self.available:
            return {}
        try:
            with self._connect() as conn:
                return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                        for t in ("runs", "persistence", "indicators")}
        except Exception:
            return {}
