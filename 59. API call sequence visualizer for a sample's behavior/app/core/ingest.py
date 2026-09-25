"""Report parsing and normalisation (architecture §3.2 / §3.3).

Formats accepted, auto-detected:

======================================  =========================================
Cuckoo ``report.json`` (v1/v2)          ``behavior.processes[].calls[]`` + processtree
CAPE ``report.json``                    same structure plus CAPE fields
CAPE behaviour ``.bson`` logs           length-prefixed BSON documents
normalised JSON Lines                   one call record per line
======================================  =========================================

Everything ends up as :class:`ApiCall` records with a canonical category, a
timestamp relative to the start of the analysis, a status, arguments and — when
loops are collapsed — a repeat count.  The process tree is rebuilt from the
report's own tree, falling back to ``parent_id`` on the processes when it is
missing or incomplete.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from app.core import bsonx
from app.core import fastjson as jsonx
from app.core.categorize import classify, normalise, is_suspicious
from app.core.model import ApiArgument, ApiCall, ProcessNode, ReportMeta

MAX_CALLS_DEFAULT = 2_000_000

CALL_ARGUMENT_NAMES = ("arguments", "args", "params", "parameters")
STATUS_TRUE = ("success", "true", "1", "ok")


# --------------------------------------------------------------------------- #
#  Format detection
# --------------------------------------------------------------------------- #
def detect_format(data: bytes, name: str = "") -> str:
    lower = (name or "").lower()
    if data[:4] == b"\x00\x00\x00\x00" or lower.endswith(".bson"):
        if bsonx.is_bson(data):
            return "cape-bson"
    if bsonx.is_bson(data) and not data[:1] in (b"{", b"["):
        return "cape-bson"
    text = data[:4096].decode("utf-8", "replace").lstrip()
    if text.startswith("{") or text.startswith("["):
        try:
            payload = jsonx.loads(data)
        except Exception:
            return "jsonl"
        if isinstance(payload, dict):
            if "behavior" in payload:
                return "cape" if ("cape" in payload or "CAPE" in str(payload.get("info", {}))[:200]) else "cuckoo"
            if "calls" in payload or "api_calls" in payload:
                return "jsonl"
        if isinstance(payload, list):
            return "jsonl" if payload and isinstance(payload[0], dict) else "unknown"
        return "cuckoo"
    return "jsonl"


# --------------------------------------------------------------------------- #
#  Timestamp / value helpers
# --------------------------------------------------------------------------- #
def _to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _timestamp(value, base: float | None) -> float:
    if value is None:
        return 0.0
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(text)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                stamp = _dt.datetime.strptime(text.replace("Z", ""), fmt)
                return stamp.timestamp() - (base or 0.0)
            except ValueError:
                continue
        return 0.0
    seconds = _to_float(value)
    if base is not None and seconds > 1e6:
        return max(0.0, seconds - base)
    return max(0.0, seconds)


def _status(value) -> str:
    if isinstance(value, bool):
        return "SUCCESS" if value else "FAILURE"
    text = str(value or "").strip().lower()
    if text in STATUS_TRUE or text == "":
        return "SUCCESS"
    return "FAILURE"


def _arguments(value) -> list[ApiArgument]:
    arguments: list[ApiArgument] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                rendered = jsonx.dumps(item, indent=None)
            elif isinstance(item, bytes):
                rendered = item.hex()
            else:
                rendered = str(item)
            arguments.append(ApiArgument(name=str(key), value=rendered))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                name = str(item.get("name", item.get("key", "arg")))
                raw = item.get("value", "")
                if isinstance(raw, (dict, list)):
                    rendered = jsonx.dumps(raw, indent=None)
                elif isinstance(raw, bytes):
                    rendered = raw.hex()
                else:
                    rendered = str(raw)
                arguments.append(ApiArgument(name=name, value=rendered))
            else:
                arguments.append(ApiArgument(name="arg", value=str(item)))
    return arguments


# --------------------------------------------------------------------------- #
#  Normalisation
# --------------------------------------------------------------------------- #
def normalise_calls(records: list[dict], processes: dict[int, ProcessNode], limit: int, warnings: list[str]) -> list[ApiCall]:
    """Turn raw call dictionaries into :class:`ApiCall` records."""
    base: float | None = None
    candidates: list[float] = []
    for record in records[:2000]:
        value = record.get("timestamp", record.get("time", record.get("ts")))
        if value is not None:
            try:
                candidates.append(float(value))
            except (TypeError, ValueError):
                continue
    if candidates:
        base = min(candidates) if min(candidates) > 1e6 else None

    calls: list[ApiCall] = []
    for index, record in enumerate(records):
        if len(calls) >= limit:
            warnings.append(f"call limit {limit} reached - the report was truncated")
            break
        if not isinstance(record, dict):
            continue
        api = str(record.get("api", record.get("function", record.get("name", "")))).strip()
        if not api:
            continue
        pid = int(_to_float(record.get("process_id", record.get("pid", 0))))
        node = processes.get(pid)
        process_name = str(
            record.get("process_name")
            or record.get("process")
            or (node.process_name if node else "")
        )
        category = normalise(str(record.get("category", "")), api)
        raw_arguments = next(
            (record[key] for key in CALL_ARGUMENT_NAMES if key in record and record[key]),
            None,
        )
        arguments = _arguments(raw_arguments)

        call = ApiCall(
            call_id=str(record.get("call_id") or f"{pid}-{index:06d}"),
            process_id=pid,
            process_name=process_name,
            parent_pid=node.parent_pid if node else record.get("parent_pid"),
            api=api,
            timestamp=_timestamp(record.get("timestamp", record.get("time", record.get("ts"))), base),
            category=category,
            status=_status(record.get("status", record.get("success"))),
            return_value=(
                str(record.get("return_value"))
                if record.get("return_value") is not None
                else None
            ),
            repeated=max(1, int(_to_float(record.get("repeated"), 1))),
            arguments=arguments,
            raw={
                key: value
                for key, value in record.items()
                if key in ("category", "thread_id", "caller", "id", "timestamp", "status")
            },
        )
        calls.append(call)

    calls.sort(key=lambda call: call.timestamp)
    return calls


def collapse_loops(calls: list[ApiCall], threshold: int = 3) -> tuple[list[ApiCall], int]:
    """Collapse consecutive identical calls into one record with a repeat count.

    "Identical" means same process, API, status and argument values — a loop of
    1000 ``ReadFile`` calls on *different* files is genuinely a thousand distinct
    events, while the same call repeated on the same handle is one behaviour.
    """
    if not calls or threshold <= 1:
        return calls, 0
    collapsed: list[ApiCall] = []
    collapsed_runs = 0
    for call in calls:
        previous = collapsed[-1] if collapsed else None
        if (
            previous is not None
            and previous.process_id == call.process_id
            and previous.api == call.api
            and previous.status == call.status
            and previous.arguments == call.arguments
            and (call.timestamp - previous.timestamp) <= 5.0
        ):
            previous.repeated += call.weight
            continue
        collapsed.append(call)
        if previous is not None:
            collapsed_runs += 0
    collapsed_runs = sum(1 for call in collapsed if call.repeated >= threshold)
    return collapsed, collapsed_runs


# --------------------------------------------------------------------------- #
#  Process tree
# --------------------------------------------------------------------------- #
def build_processes(tree: list | None, raw_processes: list | None, calls: list[ApiCall]) -> list[ProcessNode]:
    """Rebuild the process tree, preferring the report's own tree."""
    nodes: dict[int, ProcessNode] = {}

    def add_node(pid: int, name: str, parent: int | None, extra: dict | None = None) -> ProcessNode:
        node = nodes.get(pid)
        if node is None:
            node = ProcessNode(process_id=pid, process_name=name or f"pid-{pid}", parent_pid=parent)
            nodes[pid] = node
        if parent is not None and nodes.get(parent) is None:
            # Create the parent placeholder so the tree is connected even when the
            # report only lists the child.
            nodes[parent] = ProcessNode(process_id=parent, process_name=f"pid-{parent}")
        if parent is not None and pid not in nodes[parent].children:
            nodes[parent].children.append(pid)
        if extra:
            node.path = str(extra.get("path", node.path) or node.path)
            node.command_line = str(extra.get("command_line", node.command_line) or node.command_line)
            node.first_seen = _to_float(extra.get("first_seen"), node.first_seen)
        return node

    def walk(entries: list, parent: int | None = None) -> None:
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            pid = int(_to_float(entry.get("pid", entry.get("process_id", 0))))
            if not pid:
                continue
            name = str(entry.get("name", entry.get("process_name", "")))
            add_node(
                pid,
                name,
                parent if parent is not None else (
                    int(_to_float(entry["parent_id"])) if entry.get("parent_id") is not None else None
                ),
                entry,
            )
            walk(entry.get("children") or [], pid)

    if tree:
        walk(tree)

    for entry in raw_processes or []:
        if not isinstance(entry, dict):
            continue
        pid = int(_to_float(entry.get("process_id", entry.get("pid", 0))))
        if not pid:
            continue
        parent = entry.get("parent_id", entry.get("ppid"))
        add_node(
            pid,
            str(entry.get("process_name", entry.get("name", ""))),
            int(_to_float(parent)) if parent is not None else None,
            entry,
        )

    for call in calls:
        if call.process_id not in nodes:
            add_node(call.process_id, call.process_name, call.parent_pid)
        node = nodes[call.process_id]
        if not node.process_name or node.process_name.startswith("pid-"):
            node.process_name = call.process_name or node.process_name
        node.call_count += call.weight
        if call.failed:
            node.failed_calls += 1
        node.categories[call.category] = node.categories.get(call.category, 0) + call.weight
        node.first_seen = min(node.first_seen or call.timestamp, call.timestamp)

    for node in nodes.values():
        notes = []
        if node.categories.get("process") and node.categories.get("memory"):
            notes.append("process + memory APIs (injection-capable)")
        if node.failed_calls >= 5:
            notes.append(f"{node.failed_calls} failed calls (probing / anti-analysis)")
        if node.categories.get("network", 0) >= 10:
            notes.append("heavy network activity (beaconing candidate)")
        if node.categories.get("file", 0) >= 200:
            notes.append("mass file operations (ransomware / enumeration candidate)")
        node.note = "; ".join(notes)
        node.suspicious = bool(notes)

    return sorted(nodes.values(), key=lambda item: (item.parent_pid is not None, item.first_seen, item.process_id))


# --------------------------------------------------------------------------- #
#  Report metadata
# --------------------------------------------------------------------------- #
def _meta_from_cape(payload: dict, path: str, fmt: str) -> ReportMeta:
    info = payload.get("info") or {}
    target = payload.get("target") or {}
    file_info = target.get("file") or {}
    analysis = payload.get("analysis") or {}
    behavior = payload.get("behavior") or {}
    signatures = payload.get("signatures") or []
    meta = ReportMeta(
        report_id=f"report-{abs(hash(path)) % 10**10:010d}" if path else "report-memory",
        source_path=path,
        source_format=fmt,
        sample_name=str(file_info.get("name") or payload.get("sample_name") or ""),
        sample_sha256=str(file_info.get("sha256") or info.get("sha256") or ""),
        sample_md5=str(file_info.get("md5") or info.get("md5") or ""),
        machine=str(info.get("machine", {}).get("name", "") if isinstance(info.get("machine"), dict) else info.get("machine", "")),
        platform=str(info.get("platform") or analysis.get("platform") or ""),
        analysis_started=str(analysis.get("started") or info.get("started") or ""),
        duration=_to_float(analysis.get("duration", payload.get("duration", 0.0))),
        threat_score=_to_float(
            payload.get("malscore", payload.get("score", payload.get("threat_level", 0.0)))
        ),
        signatures=[
            str(sig.get("name") if isinstance(sig, dict) else sig) for sig in signatures
        ][:40],
    )
    meta.counts = {
        "processes": len(behavior.get("processes") or []),
        "tree_nodes": len(behavior.get("processtree") or []),
        "summary_sections": len(behavior.get("summary") or {}),
    }
    return meta


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #
def parse_report(data: bytes, *, name: str = "", path: str = "", limit: int = MAX_CALLS_DEFAULT, settings=None):
    """Parse a report buffer into ``(meta, calls, processes, summary)``."""
    warnings: list[str] = []
    fmt = detect_format(data, name)
    raw_records: list[dict] = []
    raw_processes: list | None = None
    tree: list | None = None
    summary: dict = {}
    meta = ReportMeta(source_path=path or name, source_format=fmt)

    if fmt == "cape-bson":
        documents = bsonx.decode_all(data)
        if not documents:
            raise ValueError("no BSON document could be decoded (unsupported or truncated log)")
        merged: dict = {}
        for document in documents:
            calls_doc = document.get("calls") or document.get("api_calls")
            if isinstance(calls_doc, list):
                # CAPE writes one document per process; the pid lives on the
                # envelope, so stamp it onto every call it carries.
                pid = document.get("process_id", document.get("pid"))
                pname = document.get("process_name", document.get("name"))
                for call in calls_doc:
                    if isinstance(call, dict):
                        call.setdefault("process_id", pid)
                        call.setdefault("process_name", pname)
                raw_records.extend(calls_doc)
                if pid:
                    raw_processes = (raw_processes or []) + [
                        {
                            "process_id": pid,
                            "process_name": pname,
                            "parent_id": document.get("parent_id"),
                            "path": document.get("path", ""),
                        }
                    ]
                continue
            for key, value in document.items():
                if key == "processes" and isinstance(value, list):
                    raw_processes = (raw_processes or []) + value
                elif key == "summary" and isinstance(value, dict):
                    summary.update(value)
                else:
                    merged.setdefault(key, value)
        meta = _meta_from_cape(merged, path or name, fmt)
        tree = merged.get("processtree")
        raw_records = raw_records or list(merged.get("calls") or [])
    elif fmt == "jsonl":
        # JSON Lines may be a stream of call records, or a stream of wrapper
        # documents (one per process) that each carry their own ``calls`` array.
        text = data.decode("utf-8", "replace")
        wrapper: dict = {}
        for record in jsonx.iter_jsonl(text):
            if not isinstance(record, dict):
                continue
            if isinstance(record.get("calls"), list) or isinstance(record.get("api_calls"), list):
                raw_records.extend(record.get("calls") or record.get("api_calls") or [])
                if record.get("processes"):
                    raw_processes = (raw_processes or []) + list(record["processes"])
                if isinstance(record.get("summary"), dict):
                    summary.update(record["summary"])
                if isinstance(record.get("processtree"), list) and not tree:
                    tree = record["processtree"]
                wrapper.update(
                    {
                        key: value
                        for key, value in record.items()
                        if key not in ("calls", "api_calls", "processes", "summary", "processtree")
                    }
                )
            else:
                raw_records.append(record)
        if wrapper:
            meta = _meta_from_cape(wrapper, path or name, fmt)
    else:
        try:
            payload = jsonx.loads(data)
        except Exception as exc:
            raise ValueError(f"report is not valid JSON: {exc}") from exc

        behavior = payload.get("behavior") if isinstance(payload, dict) else None
        if isinstance(payload, list):
            behavior = {"calls": [item for item in payload if isinstance(item, dict)]}
        behavior = behavior or {}
        raw_records = list(behavior.get("calls") or [])
        raw_processes = behavior.get("processes") or []
        tree = behavior.get("processtree")
        summary = behavior.get("summary") or {}
        for process in raw_processes:
            if isinstance(process, dict) and process.get("calls"):
                for call in process["calls"]:
                    if isinstance(call, dict):
                        call.setdefault("process_id", process.get("process_id", process.get("pid")))
                        call.setdefault("process_name", process.get("process_name", process.get("name")))
                        raw_records.append(call)
        meta = _meta_from_cape(payload, path or name, fmt)

    processes = build_processes(tree, raw_processes, [])
    calls = normalise_calls(raw_records, {node.process_id: node for node in processes}, limit, warnings)
    processes = build_processes(tree, raw_processes, calls)

    if not meta.report_id:
        # A stable identifier makes the report filename reproducible per input.
        meta.report_id = f"report-{abs(hash((path or name, len(data)))) % 10**10:010d}"
    if not meta.sample_name:
        meta.sample_name = name or Path(path).name if path or name else ""

    meta.counts["raw_calls"] = len(raw_records)
    meta.counts["calls"] = len(calls)
    meta.warnings = warnings
    if not calls:
        warnings.append("no API calls were found - check that the report contains behavior.processes[].calls[]")
    return meta, calls, processes, summary


def parse_path(path: str | Path, *, limit: int = MAX_CALLS_DEFAULT, settings=None):
    target = Path(path)
    data = target.read_bytes()
    try:
        return parse_report(data, name=target.name, path=str(target), limit=limit, settings=settings)
    except ValueError:
        # Fall back to JSON Lines for streamed behaviour logs with an odd extension.
        text = data.decode("utf-8", "replace")
        records = [record for record in jsonx.iter_jsonl(text)]
        if not records:
            raise
        processes = build_processes(None, None, [])
        calls = normalise_calls(records, {}, limit, [])
        processes = build_processes(None, None, calls)
        meta = ReportMeta(
            report_id=f"jsonl-{abs(hash(str(target))) % 10**10:010d}",
            source_path=str(target),
            source_format="jsonl",
            sample_name=target.name,
        )
        meta.counts = {"raw_calls": len(records), "calls": len(calls)}
        return meta, calls, processes, {}
