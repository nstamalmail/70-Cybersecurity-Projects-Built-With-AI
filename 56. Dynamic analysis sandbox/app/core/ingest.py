"""Behaviour telemetry ingest.

Supported inputs (auto-detected):

* **DAS session log** - our own ``.json`` (``{"session": {...}, "events": [...]}``)
  or ``.jsonl`` (one event object per line).  This is the format the built-in
  collectors and the demo harness emit.
* **CAPE / Cuckoo report** - ``report.json`` with ``behavior.processes[].calls[]``,
  ``behavior.processtree``, ``behavior.summary`` and ``network``.
* **ProcMon-style CSV** exported from Process Monitor (File System / Process /
  Registry event classes).

Everything becomes :class:`~app.core.model.BehaviorEvent` /
:class:`~app.core.model.ProcessNode` records.
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
from pathlib import Path

from app.core.model import BehaviorEvent, ProcessNode, Session

MAX_INGEST_BYTES = 256 * 1024 * 1024


# --------------------------------------------------------------------------- #
#  format detection
# --------------------------------------------------------------------------- #
def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "procmon"
    if suffix == ".jsonl":
        return "das-jsonl"
    if suffix in (".json", ".txt", ".log"):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
        except Exception:
            return "unknown"
        stripped = head.lstrip()
        if stripped.startswith("{") and '"behavior"' in head:
            return "cape"
        if '"calls"' in head and '"processes"' in head:
            return "cape"
        if stripped.startswith("{"):
            if '"events"' in head:
                return "das-json"
            # single JSON event object per file / unknown JSON
            return "das-json"
        if "Time of Day" in head or "Process Name" in head:
            return "procmon"
    return "unknown"


# --------------------------------------------------------------------------- #
#  entry point
# --------------------------------------------------------------------------- #
def ingest(path: str | Path, *, bus=None, max_events: int | None = None) -> Session:
    """Parse any supported telemetry artefact into a :class:`Session`."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No such artefact: {p}")
    if p.stat().st_size > MAX_INGEST_BYTES:
        raise ValueError(
            f"{p.name} is larger than the {MAX_INGEST_BYTES // (1024*1024)} MB ingest limit"
        )

    fmt = detect_format(p)
    if bus:
        bus.info(f"Ingesting {p.name} as '{fmt}' telemetry")

    if fmt == "das-jsonl":
        session = _parse_jsonl(p, max_events)
    elif fmt in ("das-json", "cape"):
        session = _parse_json(p, max_events)
    elif fmt == "procmon":
        session = _parse_procmon(p, max_events)
    else:
        raise ValueError(
            f"Unrecognised telemetry format for {p.name}. Expected a DAS session "
            ".json/.jsonl, a CAPE/Cuckoo report.json or a ProcMon CSV export."
        )

    session.source = session.source or fmt
    session.artifacts.append(str(p))
    if not session.sha256:
        from app.core.hashing import try_hash

        digest = try_hash(p if fmt != "procmon" else None)
        if digest:
            session.sha256 = digest
    return session


# --------------------------------------------------------------------------- #
#  DAS session log
# --------------------------------------------------------------------------- #
def _parse_jsonl(path: Path, max_events: int | None) -> Session:
    events: list[BehaviorEvent] = []
    meta: dict = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if line_no == 1 and isinstance(payload, dict) and "session" in payload:
                meta = payload.get("session") or {}
                continue
            if isinstance(payload, dict) and payload.get("event_type"):
                events.append(BehaviorEvent.from_dict(payload))
            if max_events and len(events) >= max_events:
                break
    return _finalise(events, meta, source="das", sample_name=path.name)


def _parse_json(path: Path, max_events: int | None) -> Session:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        payload = json.load(fh)

    if isinstance(payload, list):
        return _finalise(
            [BehaviorEvent.from_dict(item) for item in payload if isinstance(item, dict)],
            {},
            source="das",
            sample_name=path.name,
        )

    if not isinstance(payload, dict):
        raise ValueError("Unsupported JSON telemetry structure")

    # ---- native DAS session
    if "events" in payload:
        meta = payload.get("session") or {}
        events = [
            BehaviorEvent.from_dict(item)
            for item in payload.get("events", [])
            if isinstance(item, dict)
        ]
        session = _finalise(events, meta, source="das", sample_name=path.name, max_events=max_events)
        for key in ("warnings", "vm_name", "snapshot", "network_mode", "simulation"):
            if key in payload:
                setattr(session, key, payload[key])
        if payload.get("counters"):
            session.counters.update(payload["counters"])
        if payload.get("processes"):
            session.processes = _processes_from_meta(payload["processes"]) or session.processes
        return session

    # ---- CAPE / Cuckoo report
    if "behavior" in payload:
        return _parse_cape(payload, path, max_events)

    raise ValueError("Unsupported JSON telemetry structure")


def _parse_cape(payload: dict, path: Path, max_events: int | None) -> Session:
    behavior = payload.get("behavior") or {}
    events: list[BehaviorEvent] = []
    processes: list[ProcessNode] = []

    for proc in behavior.get("processes") or []:
        pid = int(proc.get("process_id") or 0)
        name = str(proc.get("process_name") or proc.get("name") or "")
        parent = proc.get("parent_id")
        node = ProcessNode(
            pid=pid,
            name=name,
            parent_pid=int(parent) if parent not in (None, "") else None,
            path=str(proc.get("module_path") or ""),
            command_line=str(proc.get("command_line") or ""),
            first_seen=float(proc.get("first_seen") or 0.0),
            last_seen=float(proc.get("last_seen") or 0.0),
        )
        processes.append(node)

        for call in proc.get("calls") or []:
            arguments = {}
            for arg in call.get("arguments") or []:
                if isinstance(arg, dict):
                    arguments[str(arg.get("name", ""))] = arg.get("value")
                elif isinstance(arg, (list, tuple)) and len(arg) == 2:
                    arguments[str(arg[0])] = arg[1]
            category = str(call.get("category") or "")
            function = str(call.get("api") or call.get("name") or "")
            event = BehaviorEvent(
                ts=float(call.get("timestamp") or 0.0),
                event_type=_event_type_from_api(category, function),
                process_id=pid,
                process_name=name,
                parent_pid=node.parent_pid,
                function=function,
                dll=str(call.get("dll") or ""),
                category=category,
                arguments=arguments,
                status=str(call.get("status", "") or ""),
                return_value=str(call.get("return_value", "") or ""),
                raw=call,
            )
            _enrich_from_arguments(event, arguments)
            events.append(event)
            if max_events and len(events) >= max_events:
                break

    # CAPE's consolidated summaries carry the highest-value events
    summary = behavior.get("summary") or {}
    for entry in summary.get("files") or []:
        path_value = entry if isinstance(entry, str) else str(entry)
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="dropped_file",
                process_name="(summary)",
                path=path_value,
                operation="write",
                raw={"source": "behavior.summary.files"},
            )
        )
    for entry in summary.get("keys") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="registry_set",
                process_name="(summary)",
                path=str(entry),
                operation="set",
                raw={"source": "behavior.summary.keys"},
            )
        )
    for entry in summary.get("mutexes") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="api_call",
                process_name="(summary)",
                function="CreateMutexW",
                category="sync",
                arguments={"mutex": entry},
                raw={"source": "behavior.summary.mutexes"},
            )
        )
    for entry in summary.get("executed_commands") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="shell",
                process_name="(summary)",
                arguments={"command_line": entry},
                raw={"source": "behavior.summary.executed_commands"},
            )
        )

    # network
    network = payload.get("network") or {}
    for host in network.get("hosts") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="network",
                process_name="(network)",
                dst_ip=str(host.get("ip") or ""),
                protocol="tcp",
                status=str(host.get("country_name") or ""),
                raw=host,
            )
        )
    for tcp in network.get("tcp") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="network",
                process_name="(network)",
                src_ip=str(tcp.get("src") or ""),
                dst_ip=str(tcp.get("dst") or ""),
                dst_port=_port(tcp.get("dport")),
                protocol="tcp",
                raw=tcp,
            )
        )
    for dns in network.get("dns") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="dns",
                process_name="(network)",
                arguments={"query": dns.get("request") or dns.get("hostname") or ""},
                dst_ip=str(dns.get("answers") or ""),
                protocol="dns",
                raw=dns,
            )
        )
    for http in network.get("http") or []:
        events.append(
            BehaviorEvent(
                ts=events[-1].ts if events else 0.0,
                event_type="http",
                process_name="(network)",
                path=str(http.get("uri") or ""),
                dst_ip=str(http.get("host") or ""),
                dst_port=_port(http.get("port")),
                protocol="http",
                arguments={
                    "method": http.get("method"),
                    "user-agent": (http.get("user-agent") or ""),
                },
                raw=http,
            )
        )

    meta = {
        "sha256": payload.get("target", {}).get("file", {}).get("sha256", ""),
        "md5": payload.get("target", {}).get("file", {}).get("md5", ""),
        "sample_name": payload.get("target", {}).get("file", {}).get("name", path.name),
        "started_at": str(payload.get("info", {}).get("started") or ""),
        "duration": payload.get("info", {}).get("duration"),
    }
    session = _finalise(events, meta, source="cape", sample_name=path.name, max_events=max_events)
    if processes:
        session.processes = processes
    return session


def _processes_from_meta(entries: list) -> list[ProcessNode]:
    out: list[ProcessNode] = []
    for entry in entries:
        if isinstance(entry, ProcessNode):
            out.append(entry)
        elif isinstance(entry, dict) and entry.get("pid") is not None:
            allowed = ProcessNode.__dataclass_fields__  # type: ignore[attr-defined]
            out.append(
                ProcessNode(
                    **{k: v for k, v in entry.items() if k in allowed and k != "children"}
                )
            )
    return out


def _parse_procmon(path: Path, max_events: int | None) -> Session:
    events: list[BehaviorEvent] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        delimiter = ";" if sample.count(";") > sample.count(",") else ","
        reader = csv.DictReader(fh, delimiter=delimiter)
        for row in reader:
            row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            event_class = row.get("Event Class", "")
            operation = row.get("Operation", "")
            path_value = row.get("Path", "")
            if not path_value:
                continue
            event_type = _procmon_event_type(event_class, operation)
            if event_type is None:
                continue
            process_name = row.get("Process Name", "")
            pid = _int(row.get("PID", ""))
            events.append(
                BehaviorEvent(
                    ts=_procmon_time(row.get("Time of Day", "")),
                    event_type=event_type,
                    process_id=pid or 0,
                    process_name=process_name,
                    path=path_value,
                    operation=operation,
                    arguments={"detail": row.get("Detail", "")},
                    status=row.get("Result", ""),
                    raw=row,
                )
            )
            if max_events and len(events) >= max_events:
                break
    meta = {"sample_name": path.name}
    return _finalise(events, meta, source="procmon", sample_name=path.name)


def _procmon_event_type(event_class: str, operation: str) -> str | None:
    op = operation.lower()
    if event_class == "File System":
        if "write" in op or "create" in op:
            return "file_write"
        if "delete" in op:
            return "file_delete"
        if "rename" in op:
            return "file_rename"
        if "read" in op or "query" in op:
            return "file_read"
        return "file_write"
    if event_class == "Registry":
        if "delete" in op:
            return "registry_delete"
        return "registry_set" if op.startswith("regset") or "setvalue" in op else "registry_set"
    if event_class == "Process":
        if "exit" in op.lower():
            return "process_exit"
        return "process_create"
    if event_class == "Network":
        return "network"
    return None


def _procmon_time(value: str) -> float:
    text = value.strip()
    if not text:
        return 0.0
    for fmt in ("%H:%M:%S.%f", "%H:%M:%S", "%I:%M:%S.%f %p", "%I:%M:%S %p"):
        try:
            parsed = _dt.datetime.strptime(text, fmt)
            return parsed.hour * 3600 + parsed.minute * 60 + parsed.second + parsed.microsecond / 1e6
        except ValueError:
            continue
    return 0.0


def _int(value) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def _port(value) -> int | None:
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value).rsplit(":", 1)[-1])
        except Exception:
            return None


# --------------------------------------------------------------------------- #
#  normalisation helpers
# --------------------------------------------------------------------------- #
def _event_type_from_api(category: str, function: str) -> str:
    fn = (function or "").lower()
    cat = (category or "").lower()
    if fn.startswith("reg") or "deletevalue" in fn or "setvalue" in fn:
        return "registry_delete" if "delete" in fn else "registry_set"
    if fn in ("createfilew", "createfilea", "ntcreatefile", "openfile"):
        return "file_write"
    if fn in ("writefile", "ntwritefile"):
        return "file_write"
    if fn in ("deletefilew", "deletefilea", "ntdeletefile"):
        return "file_delete"
    if fn in ("movefilew", "movefilea", "ntrenamefile", "setfileinformationbyhandle"):
        return "file_rename"
    if fn in ("createservicew", "createservicea", "openscmanagerw"):
        return "service_create"
    if "schrpc" in fn or "schedul" in fn:
        return "task_create"
    if fn in ("createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext"):
        return "process_inject"
    if fn in ("createprocessw", "createprocessa", "shellexecutew", "shellexecutea", "winexec", "createprocessasuserw"):
        return "process_create"
    if fn.endswith("exit") or fn in ("terminateprocess",):
        return "process_exit"
    if fn in ("loadlibraryw", "loadlibrarya", "loadlibraryexw", "ldrloaddll"):
        return "module_load"
    if fn in ("connect", "internetconnecta", "internetopenurl", "winhttpconnect", "wsaconnect", "httpsendrequest"):
        return "network"
    if fn in ("getaddrinfo", "internetgetaddrinfo", "dnsquery_a", "dnsquery_w", "gethostbyname"):
        return "dns"
    if cat in ("network",):
        return "network"
    if cat in ("file", "filesystem"):
        return "file_write"
    if cat in ("registry", "keys"):
        return "registry_set"
    if cat in ("process",):
        return "process_create"
    return "api_call"


def _enrich_from_arguments(event: BehaviorEvent, arguments: dict) -> None:
    """Lift common argument names onto the event so views can filter cheaply."""
    if not arguments:
        return
    lower = {str(k).lower(): v for k, v in arguments.items()}

    def pick(*names):
        for name in names:
            if name in lower and lower[name] not in (None, ""):
                return lower[name]
        return None

    file_name = pick("filepath", "file_name", "filename", "path", "filepath_2")
    if file_name and not event.path:
        candidate = str(file_name)
        looks_like_path = ("\\" in candidate or "/" in candidate or "." in candidate)
        if looks_like_path and candidate not in ("0x00000000", "0"):
            event.path = candidate

    if event.event_type in ("registry_set", "registry_delete"):
        key = pick("regkey", "key", "full_name", "hkey")
        if key:
            event.path = str(key)
        value_name = pick("valuename", "value_name", "regvalue")
        if value_name:
            event.arguments["value_name"] = value_name
        value_data = pick("value", "data", "buff")
        if value_data is not None:
            event.arguments.setdefault("value_data", value_data)

    if event.event_type == "network":
        ip = pick("hostname", "ip", "ip_address", "address")
        if ip:
            event.dst_ip = str(ip)
        port = pick("port", "server_port", "dport")
        if port:
            event.dst_port = _port(port)

    if event.event_type == "dns":
        query = pick("hostname", "query", "name")
        if query:
            event.arguments.setdefault("query", query)

    if event.event_type in ("process_create", "process_inject"):
        cmd = pick("commandline", "command_line", "cmdline", "applicationname")
        if cmd:
            event.arguments.setdefault("command_line", cmd)
        target = pick("processhandle", "target_pid", "process_id")
        if target:
            event.arguments.setdefault("target_pid", target)

    if event.event_type == "service_create":
        name = pick("servicename", "service_name")
        if name:
            event.arguments.setdefault("service_name", name)
        binary = pick("binarypathname", "binary_path")
        if binary:
            event.arguments.setdefault("binary_path", binary)

    if event.event_type == "task_create":
        name = pick("taskname", "task_name")
        if name:
            event.arguments.setdefault("task_name", name)

    if event.event_type == "module_load":
        module = pick("modulename", "module_name")
        if module:
            event.arguments.setdefault("module", module)


# --------------------------------------------------------------------------- #
#  finalisation
# --------------------------------------------------------------------------- #
def _finalise(
    events: list[BehaviorEvent],
    meta: dict,
    *,
    source: str,
    sample_name: str,
    max_events: int | None = None,
) -> Session:
    events = [e for e in events if e.event_type]
    events.sort(key=lambda e: float(e.ts or 0.0))
    if max_events:
        events = events[:max_events]
    for index, event in enumerate(events):
        if not event.event_id:
            event.event_id = f"ev-{index:06d}"

    session = Session(
        session_id=str(meta.get("session_id") or _make_id()),
        sample_name=str(meta.get("sample_name") or sample_name),
        sample_path=str(meta.get("sample_path") or ""),
        sha256=str(meta.get("sha256") or ""),
        md5=str(meta.get("md5") or ""),
        started_at=str(meta.get("started_at") or ""),
        duration=float(meta.get("duration") or (events[-1].ts if events else 0.0) or 0.0),
        source=source,
        vm_name=str(meta.get("vm_name") or ""),
        snapshot=str(meta.get("snapshot") or ""),
        network_mode=str(meta.get("network_mode") or ""),
        events=events,
        counters=_counters(events),
        meta={k: v for k, v in meta.items() if k not in ("events",)},
        simulation=bool(meta.get("simulation", False)),
    )
    if not session.processes:
        session.processes = _derive_processes(events)
    return session


def _make_id() -> str:
    return f"das-{_dt.datetime.now():%Y%m%d-%H%M%S}"


def _counters(events: list[BehaviorEvent]) -> dict:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.event_type] = counts.get(event.event_type, 0) + 1
    return counts


def _derive_processes(events: list[BehaviorEvent]) -> list[ProcessNode]:
    """Rebuild a process list (and parent links) from the event stream."""
    seen: dict[int, ProcessNode] = {}
    for event in events:
        if not event.process_id and not event.process_name:
            continue
        pid = int(event.process_id or 0)
        node = seen.get(pid)
        if node is None:
            node = ProcessNode(
                pid=pid,
                name=event.process_name,
                parent_pid=event.parent_pid,
                first_seen=float(event.ts or 0.0),
            )
            seen[pid] = node
        node.last_seen = max(node.last_seen, float(event.ts or 0.0))
    return sorted(seen.values(), key=lambda p: p.pid)
