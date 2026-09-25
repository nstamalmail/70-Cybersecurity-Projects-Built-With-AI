"""Canonical data model (architecture §3.3 / §3.6 / §3.7).

Every parser in this workbench — Cuckoo JSON, CAPE JSON, CAPE BSON, normalised
JSON Lines — produces the same :class:`ApiCall` records, so the timeline, the
pattern matcher, the filters, the heatmap and the exporters never need to know
where the data came from.
"""
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
    """One normalised API call."""

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

    # ------------------------------------------------------------- accessors
    @property
    def arg_map(self) -> dict[str, str]:
        return {argument.name.lower(): argument.value for argument in self.arguments}

    def arg(self, *names: str, default: str = "") -> str:
        """Case-insensitive argument lookup (Cuckoo and CAPE disagree on naming)."""
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
        """How many raw calls this record stands for (loop collapse)."""
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

    def to_dict(self) -> dict:
        data = asdict(self)
        data["arguments"] = [argument.to_dict() for argument in self.arguments]
        return data


@dataclass
class ProcessNode:
    """One node of the reconstructed process tree."""

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

    @property
    def depth_marker(self) -> str:
        return f"PID {self.process_id}"

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

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReportMeta:
    """Report-level metadata (sample, duration, score, signatures)."""

    report_id: str = ""
    source_path: str = ""
    source_format: str = "unknown"      # cuckoo | cape | cape-bson | jsonl
    sample_name: str = ""
    sample_sha256: str = ""
    sample_md5: str = ""
    machine: str = ""
    platform: str = ""
    analysis_started: str = ""
    duration: float = 0.0
    threat_score: float = 0.0
    signatures: list[str] = field(default_factory=list)
    parsed_at: str = field(default_factory=_now)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NGramHit:
    """One frequent ordered tuple of APIs."""

    sequence: list[str] = field(default_factory=list)
    occurrences: int = 0
    length: int = 0
    score: float = 0.0
    process_id: int | None = None

    @property
    def text(self) -> str:
        return " -> ".join(self.sequence)

    def to_row(self) -> list:
        return [
            self.occurrences,
            self.length,
            f"{self.score:.0f}",
            self.process_id if self.process_id is not None else "all",
            self.text,
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CallSequence:
    """A mined sequence, either a cluster (support) or a concrete instance."""

    sequence: list[str] = field(default_factory=list)
    support: int = 0
    length: int = 0
    score: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0
    process_id: int | None = None
    process_name: str = ""
    call_ids: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " -> ".join(self.sequence)

    @property
    def span(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    def to_row(self) -> list:
        return [
            self.length,
            self.support,
            self.process_name or (self.process_id if self.process_id is not None else "-"),
            f"{self.start_time:.2f}",
            f"{self.span:.2f}",
            self.text,
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Transition:
    """A first-order Markov transition between two APIs."""

    source: str
    target: str
    count: int = 0
    probability: float = 0.0
    process_id: int | None = None

    def to_row(self) -> list:
        return [
            self.source,
            self.target,
            self.count,
            f"{self.probability * 100:.1f}%",
            self.process_id if self.process_id is not None else "all",
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PatternMatch:
    """One hit of a behavioural sequence pattern."""

    pattern_id: str
    name: str
    severity: str = "medium"
    process_id: int = 0
    process_name: str = ""
    start_ts: float = 0.0
    end_ts: float = 0.0
    call_ids: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    description: str = ""
    references: list[str] = field(default_factory=list)
    target: str = ""

    @property
    def span(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def to_row(self) -> list:
        return [
            self.severity,
            self.name,
            self.process_name or "-",
            f"{self.start_ts:.2f}",
            f"{self.span:.2f}",
            " -> ".join(self.apis),
            self.target or "-",
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BehaviorReport:
    """Everything parsed out of one sandbox report."""

    meta: ReportMeta
    calls: list[ApiCall] = field(default_factory=list)
    processes: list[ProcessNode] = field(default_factory=list)
    matches: list[PatternMatch] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    raw_counts: dict[str, int] = field(default_factory=dict)
    severity: str = "info"
    score: int = 0
    report: object = None
    case_dir: str = ""

    @property
    def duration(self) -> float:
        return max((call.timestamp for call in self.calls), default=0.0)

    def process(self, process_id: int) -> ProcessNode | None:
        return next((node for node in self.processes if node.process_id == process_id), None)

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for call in self.calls:
            counts[call.category] = counts.get(call.category, 0) + call.weight
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def summary_rows(self) -> list[tuple[str, str]]:
        return [
            ("report", self.meta.report_id),
            ("format", self.meta.source_format),
            ("sample", self.meta.sample_name or "-"),
            ("sha256", self.meta.sample_sha256 or "-"),
            ("api calls", f"{len(self.calls)} (raw {self.meta.counts.get('raw_calls', len(self.calls))})"),
            ("processes", str(len(self.processes))),
            ("duration", f"{self.duration:.1f}s of behaviour"),
            ("patterns matched", str(len(self.matches))),
            ("IOCs", str(len(self.iocs))),
            ("severity", self.severity.upper()),
            ("score", f"{self.score}/100"),
        ]
