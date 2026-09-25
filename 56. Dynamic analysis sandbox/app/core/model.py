"""Normalised behaviour telemetry model.

Every collector (guest agent, CAPE/Cuckoo report, DAS session log) is normalised
into these structures so the timeline, process tree and IOC extraction never need
to know where the data came from.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

# event_type -> timeline lane / colour category
CATEGORY_OF = {
    "process_create": "process",
    "process_exit": "process",
    "process_inject": "process",
    "module_load": "system",
    "api_call": "system",
    "file_write": "file",
    "file_read": "file",
    "file_delete": "file",
    "file_rename": "file",
    "dropped_file": "file",
    "registry_set": "registry",
    "registry_delete": "registry",
    "service_create": "persistence",
    "task_create": "persistence",
    "network": "network",
    "dns": "dns",
    "http": "network",
    "shell": "process",
}

EVENT_LABELS = {
    "process_create": "Process created",
    "process_exit": "Process exited",
    "process_inject": "Process injection",
    "module_load": "Module loaded",
    "api_call": "API call",
    "file_write": "File written",
    "file_read": "File read",
    "file_delete": "File deleted",
    "file_rename": "File renamed",
    "dropped_file": "Dropped file",
    "registry_set": "Registry set",
    "registry_delete": "Registry deleted",
    "service_create": "Service created",
    "task_create": "Scheduled task created",
    "network": "Network connection",
    "dns": "DNS query",
    "http": "HTTP request",
    "shell": "Command executed",
}


@dataclass
class BehaviorEvent:
    """One telemetry record."""

    ts: float = 0.0
    event_type: str = "api_call"
    process_id: int = 0
    process_name: str = ""
    parent_pid: int | None = None
    event_id: str = ""
    dll: str = ""
    function: str = ""
    category: str = ""
    arguments: dict = field(default_factory=dict)
    path: str = ""
    operation: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    bytes_sent: int | None = None
    bytes_received: int | None = None
    status: str = ""
    return_value: str = ""
    data: str = ""
    sha256: str = ""
    raw: dict = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    @property
    def lane(self) -> str:
        explicit = self.category or CATEGORY_OF.get(self.event_type, "system")
        return {
            "filesystem": "file",
            "keys": "registry",
            "process": "process",
            "network": "network",
        }.get(explicit, explicit)

    @property
    def label(self) -> str:
        base = EVENT_LABELS.get(self.event_type, self.event_type)
        if self.event_type == "api_call" and self.function:
            return f"{self.dll}!{self.function}" if self.dll else self.function
        return base

    def summary(self) -> str:
        if self.event_type == "api_call":
            args = ", ".join(f"{k}={v}" for k, v in list(self.arguments.items())[:3])
            return f"{self.function}({args}) \u2192 {self.return_value or self.status}"
        if self.event_type in ("file_write", "file_read", "file_delete", "file_rename", "dropped_file"):
            extra = f" ({self.sha256[:16]}\u2026)" if self.sha256 else ""
            return f"{self.operation or self.event_type}: {self.path}{extra}"
        if self.event_type in ("registry_set", "registry_delete"):
            value = self.arguments.get("value_name", "")
            return f"{self.path}" + (f" [{value}]" if value else "")
        if self.event_type in ("network", "dns", "http"):
            target = self.dst_ip or self.arguments.get("query") or self.path
            port = f":{self.dst_port}" if self.dst_port else ""
            return f"{self.protocol or self.event_type} {target}{port}"
        if self.event_type == "process_create":
            return f"{self.process_name} (pid {self.process_id}) {self.arguments.get('command_line', '')}"[:400]
        if self.event_type == "service_create":
            return f"service {self.arguments.get('service_name', '')} \u2192 {self.arguments.get('binary_path', '')}"
        if self.event_type == "task_create":
            return f"task {self.arguments.get('task_name', '')} \u2192 {self.arguments.get('command', '')}"
        return self.data or self.label

    def to_dict(self) -> dict:
        return {
            "ts": round(float(self.ts), 4),
            "event_type": self.event_type,
            "event_id": self.event_id,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "parent_pid": self.parent_pid,
            "dll": self.dll,
            "function": self.function,
            "category": self.category,
            "arguments": self.arguments,
            "path": self.path,
            "operation": self.operation,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "status": self.status,
            "return_value": self.return_value,
            "data": self.data,
            "sha256": self.sha256,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "BehaviorEvent":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        values = {k: v for k, v in payload.items() if k in known and k != "raw"}
        event = cls(**values)
        event.raw = payload.get("raw") or {}
        return event

    def clock(self) -> str:
        total = max(0.0, float(self.ts))
        return f"{int(total // 60):02d}:{total % 60:06.3f}"


@dataclass
class ProcessNode:
    """A process observed during the run."""

    pid: int
    name: str = ""
    parent_pid: int | None = None
    path: str = ""
    command_line: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    user: str = ""
    status: str = "seen"
    children: list["ProcessNode"] = field(default_factory=list)
    risk: str = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "parent_pid": self.parent_pid,
            "path": self.path,
            "command_line": self.command_line,
            "first_seen": round(self.first_seen, 4),
            "last_seen": round(self.last_seen, 4),
            "user": self.user,
            "status": self.status,
            "risk": self.risk,
        }


@dataclass
class Session:
    """One detonation / ingest run."""

    session_id: str
    sample_name: str
    sample_path: str = ""
    sha256: str = ""
    md5: str = ""
    started_at: str = ""
    duration: float = 0.0
    source: str = "session"          # das | cape | cuckoo | session
    vm_name: str = ""
    snapshot: str = ""
    network_mode: str = ""
    events: list[BehaviorEvent] = field(default_factory=list)
    processes: list[ProcessNode] = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    simulation: bool = False

    # -------------------------------------------------------------- helpers
    def event_types(self) -> list[str]:
        return sorted({e.event_type for e in self.events})

    def by_type(self, *types: str) -> list[BehaviorEvent]:
        wanted = set(types)
        return [e for e in self.events if e.event_type in wanted]

    def process_by_pid(self, pid: int) -> ProcessNode | None:
        for node in self.processes:
            if node.pid == pid:
                return node
        return None

    def roots(self) -> list[ProcessNode]:
        by_pid = {p.pid: p for p in self.processes}
        roots = [p for p in self.processes if p.parent_pid not in by_pid]
        return roots or self.processes[:1]

    def now_stamp(self) -> str:
        return self.started_at or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
