"""Core data models shared across the pipeline."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

SEVERITIES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
SEVERITY_WEIGHT = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class RawEvent:
    """A single raw log line as captured by an ingest source."""

    raw: str
    source_name: str = "unknown"
    source_type: str = "unknown"
    ts: float = field(default_factory=time.time)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"RawEvent({self.source_name}: {self.raw[:80]!r})"


@dataclass
class NormalizedEvent:
    """A raw line mapped onto the common schema."""

    ts: float
    source: str
    source_type: str
    host: str
    severity: str
    message: str
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    @property
    def severity_weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 1)

    def display_time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))


@dataclass
class Alert:
    """A correlation rule match."""

    ts: float
    rule_id: str
    rule_name: str
    severity: str
    summary: str
    group_key: str = "global"
    count: int = 1
    status: str = "open"
    fields: dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def display_time(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))