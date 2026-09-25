"""Domain models shared between engines, storage and GUI."""

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

FIM_CATEGORIES = ("FIM",)
PROC_CATEGORIES = ("PROCESS", "SYSTEM")


def highest_severity(names):
    best = "INFO"
    for n in names:
        if SEV_RANK.get(n, 0) > SEV_RANK.get(best, 0):
            best = n
    return best


@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float
    sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChangeRecord:
    """One detected difference between baseline and disk during verification."""

    path: str
    change: str  # ADDED | MODIFIED | DELETED
    old: Optional[FileRecord] = None
    new: Optional[FileRecord] = None
    source: str = "sweep"  # sweep | realtime


@dataclass
class Alert:
    timestamp: float
    severity: str  # INFO..CRITICAL
    category: str  # FIM | PROCESS | SYSTEM
    event_type: str  # file_modified, suspicious_process, file_burst, ...
    title: str
    details: dict = field(default_factory=dict)
    acknowledged: int = 0
    id: Optional[int] = None

    def details_json(self) -> str:
        try:
            return json.dumps(self.details, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            return "{}"

    @staticmethod
    def from_row(row) -> "Alert":
        try:
            details = json.loads(row["details"] or "{}")
        except (TypeError, ValueError):
            details = {}
        return Alert(
            id=row["id"],
            timestamp=row["timestamp"],
            severity=row["severity"],
            category=row["category"],
            event_type=row["event_type"],
            title=row["title"],
            details=details,
            acknowledged=row["acknowledged"],
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: list
    user: str
    cpu: float = 0.0
    mem: float = 0.0
    create_time: Optional[float] = None
    parent_name: Optional[str] = None
    suspicious: bool = False
    reasons: list = field(default_factory=list)

    @property
    def cmdline_str(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else ""
