"""Structured in-app log bus."""
from __future__ import annotations

import datetime as _dt
import traceback
from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal

from app.config import logs_dir

LEVELS = ("debug", "info", "warn", "error", "success")


@dataclass
class LogRecord:
    ts: _dt.datetime
    level: str
    message: str
    source: str = "app"

    def format(self) -> str:
        return f"[{self.ts:%H:%M:%S}] {self.level.upper():<7} {self.message}"


class LogBus(QObject):
    record = Signal(object)

    def __init__(self, source: str = "app", echo_file: bool = True) -> None:
        super().__init__()
        self.source = source
        self.echo_file = echo_file
        self.records: list[LogRecord] = []
        self._log_path = logs_dir() / "session.log"

    def log(self, message: str, level: str = "info", source: str | None = None) -> LogRecord:
        rec = LogRecord(
            ts=_dt.datetime.now(),
            level=level if level in LEVELS else "info",
            message=str(message),
            source=source or self.source,
        )
        self.records.append(rec)
        if self.echo_file:
            try:
                with self._log_path.open("a", encoding="utf-8") as fh:
                    fh.write(rec.format() + "\n")
            except Exception:
                pass
        self.record.emit(rec)
        return rec

    def debug(self, message: str) -> LogRecord:
        return self.log(message, "debug")

    def info(self, message: str) -> LogRecord:
        return self.log(message, "info")

    def warn(self, message: str) -> LogRecord:
        return self.log(message, "warn")

    def error(self, message: str) -> LogRecord:
        return self.log(message, "error")

    def success(self, message: str) -> LogRecord:
        return self.log(message, "success")

    def exception(self, message: str, exc: BaseException | None = None) -> LogRecord:
        detail = "".join(
            traceback.format_exception_only(type(exc), exc)
        ).strip() if exc else ""
        return self.log(f"{message}: {detail}" if detail else message, "error")

    def clear(self) -> None:
        self.records.clear()

    def to_text(self) -> str:
        return "\n".join(r.format() for r in self.records)

    @property
    def log_path(self):
        return self._log_path
