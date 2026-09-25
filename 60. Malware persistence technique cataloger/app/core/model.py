"""Canonical data model for the Malware Persistence Technique Cataloger."""
from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class ApiArgument:
    name: str
    value: str

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value}


@dataclass
class ApiCall:
    call_id: str
    process_id: int
    process_name: str
    api: str
    timestamp: float = 0.0
    category: str = "system"
    status: str = "SUCCESS"
    return_value: str | None = None
    repeated: int = 1
    parent_pid: int | None = None
    arguments: list[ApiArgument] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def arg_map(self) -> dict[str, str]:
        return {argument.name.lower(): argument.value for argument in self.arguments}

    def arg(self, *names: str, default: str = "") -> str:
        lowered = self.arg_map
        for name in names:
            value = lowered.get(name.lower())
            if value not in (None, ""):
                return str(value)
        return default

    @property
    def arguments_text(self) -> str:
        return ", ".join(f"{argument.name}={argument.value}" for argument in self.arguments)

    @property
    def failed(self) -> bool:
        return (self.status or "").upper() in ("FAILURE", "FAILED", "ERROR")

    @property
    def weight(self) -> int:
        return max(1, int(self.repeated))

    def to_row(self) -> list:
        return [
            f"{self.timestamp:8.3f}",
            self.process_id,
            self.process_name,
            self.category,
            self.api,
            self.status,
            self.repeated,
            self.arguments_text[:160],
            self.return_value or "",
        ]


@dataclass
class PersistenceArtifact:
    """One identified persistence mechanism."""
    technique_id: str
    technique_name: str
    severity: str = "medium"
    source: str = "behavior"
    key_path: str = ""
    value_name: str = ""
    value_data: str = ""
    service_name: str = ""
    task_name: str = ""
    binary_path: str = ""
    process_id: int = 0
    process_name: str = ""
    timestamp: float = 0.0
    confidence: float = 0.8
    evidence: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_row(self) -> list:
        return [
            self.severity,
            self.technique_id,
            self.technique_name,
            self.source,
            self.key_path or self.service_name or self.task_name or self.binary_path,
            f"{self.confidence:.2f}",
            "; ".join(self.evidence[:3]),
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PersistenceTechnique:
    technique_id: str
    name: str
    tactic: str = "Persistence"
    description: str = ""
    severity: str = "medium"
    detection_hints: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class ProcessNode:
    process_id: int
    process_name: str
    parent_pid: int | None = None
    path: str = ""
    command_line: str = ""
    first_seen: float = 0.0
    call_count: int = 0
    failed_calls: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    children: list[int] = field(default_factory=list)
    suspicious: bool = False
    note: str = ""

    def to_row(self) -> list:
        return [
            self.process_name,
            self.process_id,
            self.parent_pid if self.parent_pid is not None else "-",
            f"{self.first_seen:.2f}",
            self.call_count,
            self.failed_calls,
            ", ".join(f"{name}:{count}" for name, count in sorted(self.categories.items(), key=lambda kv: -kv[1])[:4]),
            self.path or "-",
        ]


@dataclass
class ReportMeta:
    report_id: str = ""
    source_path: str = ""
    source_format: str = "unknown"
    sample_name: str = ""
    sample_sha256: str = ""
    machine: str = ""
    analysis_started: str = ""
    duration: float = 0.0
    threat_score: float = 0.0
    signatures: list[str] = field(default_factory=list)
    parsed_at: str = field(default_factory=_now)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
