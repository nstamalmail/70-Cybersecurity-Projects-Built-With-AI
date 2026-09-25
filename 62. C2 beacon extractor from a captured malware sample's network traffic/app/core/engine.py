"""Analysis engine: ingest -> detect persistence -> catalog -> report."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.config import APP, demo_dir
from app.core import detection
from app.core.model import ApiArgument, ApiCall, PersistenceArtifact, ProcessNode, ReportMeta
from app.core.store import CaseStore
from app.reporting import Report


@dataclass
class AnalysisResult:
    meta: ReportMeta = field(default_factory=ReportMeta)
    calls: list[ApiCall] = field(default_factory=list)
    processes: list[ProcessNode] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    artifacts: list[PersistenceArtifact] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    severity: str = "info"
    score: int = 0
    source_path: str = ""
    source_name: str = ""
    source_format: str = "unknown"
    source_size: int = 0
    notes: list[str] = field(default_factory=list)
    report: Report | None = None

    def summary_rows(self) -> list[tuple[str, str]]:
        return [
            ("source", self.source_name or self.meta.sample_name or "-"),
            ("format", self.source_format),
            ("sample sha256", self.meta.sample_sha256 or "-"),
            ("api calls", str(len(self.calls))),
            ("processes", str(len(self.processes))),
            ("persistence", str(len(self.artifacts))),
            ("indicators", str(len(self.iocs))),
            ("severity", f"{self.severity.upper()} ({self.score}/100)"),
        ]

    @property
    def duration(self) -> float:
        return max((call.timestamp for call in self.calls), default=0.0)

    @property
    def call_count(self) -> int:
        return sum(call.weight for call in self.calls)

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for call in self.calls:
            counts[call.category] = counts.get(call.category, 0) + call.weight
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def iocs_as_report_items(self) -> list[dict]:
        return [
            {
                "ioc_type": item.get("type", ""),
                "value": item.get("value", ""),
                "source": item.get("source", ""),
                "confidence": item.get("confidence", 0.5),
                "context": item.get("context", ""),
            }
            for item in self.iocs
        ]


class Engine:
    def __init__(self, settings, bus=None) -> None:
        self.settings = settings
        self.bus = bus
        self._store: CaseStore | None = None

    @property
    def store(self) -> CaseStore:
        if self._store is None:
            self._store = CaseStore()
        return self._store

    def log(self, message: str, level: str = "info") -> None:
        if self.bus is not None:
            try:
                self.bus.log(message, level)
                return
            except Exception:
                pass
        print(f"[{level}] {message}")

    def analyse_bytes(self, data: bytes, *, name: str = "", path: str = "", progress=None) -> AnalysisResult:
        settings = self.settings
        min_severity = str(settings.get("pattern_min_severity", "low") or "low")

        def tick(fraction: float, message: str) -> None:
            if progress:
                progress(fraction, message)

        tick(0.05, f"Parsing {name or 'report'}...")
        meta, calls, processes, summary = self._parse(data, name, path)
        result = AnalysisResult(
            meta=meta, processes=processes, summary=summary,
            source_path=path or name, source_name=name or Path(path or "").name,
            source_format=meta.source_format, source_size=len(data),
        )
        self.log(f"Parsed {meta.source_format} report: {len(calls)} calls, {len(processes)} processes")

        tick(0.3, "Detecting persistence mechanisms...")
        result.artifacts = detection.match_all(calls)
        self.log(f"Detected {len(result.artifacts)} persistence mechanisms")

        tick(0.6, "Extracting indicators...")
        result.iocs = self._extract_iocs(calls, result.artifacts)
        self.log(f"Extracted {len(result.iocs)} indicators")

        tick(0.8, "Scoring...")
        result.score, result.severity = detection.score_matches(result.artifacts)

        if not calls:
            result.notes.append("No API calls were parsed.")

        result.report = self.build_report(result)
        tick(1.0, "Analysis complete")
        return result

    def _parse(self, data: bytes, name: str, path: str):
        """Simple JSON report parser."""
        from app.core import fastjson as jsonx
        import datetime as _dt

        warnings = []
        try:
            payload = jsonx.loads(data)
        except Exception:
            return ReportMeta(source_format="unknown"), [], [], {}

        if not isinstance(payload, dict):
            return ReportMeta(source_format="unknown"), [], [], {}

        behavior = payload.get("behavior") or {}
        raw_calls = list(behavior.get("calls") or [])
        raw_processes = behavior.get("processes") or []
        summary = behavior.get("summary") or {}
        # Also extract calls nested inside process entries
        for process in raw_processes:
            if isinstance(process, dict) and process.get("calls"):
                for call in process["calls"]:
                    if isinstance(call, dict):
                        call.setdefault("process_id", process.get("process_id", process.get("pid")))
                        call.setdefault("process_name", process.get("process_name", process.get("name")))
                        raw_calls.append(call)

        meta = ReportMeta(
            report_id=f"report-{abs(hash(path or name)) % 10**10:010d}",
            source_path=path or name,
            source_format="cape" if "cape" in str(payload.get("info", {})).lower() else "cuckoo",
            sample_name=name,
        )
        info = payload.get("info") or {}
        target = payload.get("target") or {}
        file_info = target.get("file") or {}
        meta.sample_sha256 = str(file_info.get("sha256") or "")
        meta.machine = str(info.get("machine", {}).get("name", "") if isinstance(info.get("machine"), dict) else info.get("machine", ""))
        meta.threat_score = float(payload.get("malscore", payload.get("score", 0.0)))
        meta.signatures = [str(s.get("name") if isinstance(s, dict) else s) for s in (payload.get("signatures") or [])]

        processes = {}
        for entry in raw_processes:
            pid = int(float(entry.get("process_id", entry.get("pid", 0))))
            if pid:
                processes[pid] = ProcessNode(
                    process_id=pid,
                    process_name=entry.get("process_name", entry.get("name", f"pid-{pid}")),
                    parent_pid=int(float(entry.get("parent_id", 0))) or None,
                )

        calls = []
        base = None
        for record in raw_calls:
            if not isinstance(record, dict):
                continue
            api = str(record.get("api", "")).strip()
            if not api:
                continue
            pid = int(float(record.get("process_id", record.get("pid", 0))))
            node = processes.get(pid)
            cat = str(record.get("category", "")).lower().strip()
            if cat in ("reg", "registry"):
                cat = "registry"
            elif cat in ("file", "filesystem"):
                cat = "file"
            elif cat in ("network", "net", "socket"):
                cat = "network"
            elif cat in ("process", "proc", "thread"):
                cat = "process"
            elif cat in ("memory", "mem"):
                cat = "memory"
            elif cat in ("sync", "mutex"):
                cat = "sync"
            elif cat in ("system", "service", "services"):
                cat = "system"
            elif cat in ("crypto",):
                cat = "crypto"
            else:
                cat = cat or "system"

            raw_args = record.get("arguments") or record.get("args") or {}
            arguments = []
            if isinstance(raw_args, dict):
                for k, v in raw_args.items():
                    arguments.append(ApiArgument(name=str(k), value=str(v) if not isinstance(v, (dict, list)) else str(v)[:200]))

            stamp = float(record.get("timestamp", record.get("time", 0.0)))
            calls.append(ApiCall(
                call_id=record.get("call_id") or f"{pid}-{len(calls):06d}",
                process_id=pid,
                process_name=node.process_name if node else f"pid-{pid}",
                api=api, timestamp=stamp, category=cat,
                status=str(record.get("status", "SUCCESS")).upper(),
                return_value=str(record.get("return_value")) if record.get("return_value") is not None else None,
                arguments=arguments, parent_pid=node.parent_pid if node else None,
            ))

        calls.sort(key=lambda c: c.timestamp)

        for call in calls:
            if call.process_id not in processes:
                processes[call.process_id] = ProcessNode(process_id=call.process_id, process_name=call.process_name)
            node = processes[call.process_id]
            node.call_count += call.weight
            node.categories[call.category] = node.categories.get(call.category, 0) + call.weight
            node.first_seen = min(node.first_seen or call.timestamp, call.timestamp)

        return meta, calls, list(processes.values()), summary

    def _extract_iocs(self, calls, artifacts):
        iocs = []
        seen = set()
        for artifact in artifacts:
            if artifact.key_path:
                key = ("registry", artifact.key_path)
                if key not in seen:
                    seen.add(key)
                    iocs.append({"type": "registry", "value": artifact.key_path, "source": artifact.technique_id, "confidence": 0.9})
            if artifact.service_name:
                key = ("service", artifact.service_name)
                if key not in seen:
                    seen.add(key)
                    iocs.append({"type": "service", "value": artifact.service_name, "source": artifact.technique_id, "confidence": 0.9})
        for call in calls:
            if call.category == "network":
                host = call.arg("hostname", "host_name", "ip_address", default="")
                if host and host not in ("127.0.0.1", "localhost"):
                    key = ("domain" if not host.replace(".", "").isdigit() else "ipv4", host)
                    if key not in seen:
                        seen.add(key)
                        iocs.append({"type": key[0], "value": host, "source": call.api, "confidence": 0.8})
            if call.category == "file":
                fp = call.arg("file_name", "filename", default="")
                if fp and "system32" not in fp.lower() and len(fp) > 5:
                    key = ("file", fp)
                    if key not in seen:
                        seen.add(key)
                        iocs.append({"type": "file", "value": fp, "source": call.api, "confidence": 0.7})
        return iocs

    def build_report(self, result: AnalysisResult) -> Report:
        report = Report(
            title=APP["report_title"],
            subtitle=f"{result.source_name or result.meta.sample_name or 'sandbox report'}",
            verdict=result.severity,
            risk_score=result.score,
            run_id=result.meta.report_id or f"{APP['slug']}-run",
        )
        report.iocs = result.iocs_as_report_items()
        report.summary = self._narrative(result)
        report.meta = {
            "Source": result.source_name or "-",
            "Format": result.source_format,
            "SHA-256": result.meta.sample_sha256 or "-",
            "Machine": result.meta.machine or "-",
            "API calls": str(len(result.calls)),
            "Processes": str(len(result.processes)),
            "Persistence mechanisms": str(len(result.artifacts)),
            "Indicators": str(len(result.iocs)),
            "Verdict": f"{result.severity.upper()} ({result.score}/100)",
        }

        if result.artifacts:
            report.add_table(
                "Persistence mechanisms detected",
                ["Severity", "Technique", "Name", "Source", "Evidence", "Confidence", "Details"],
                [a.to_row() for a in result.artifacts[:40]],
                note="Ordered by timestamp; mapped to MITRE ATT&CK persistence techniques.",
            )
        else:
            report.add_text("Persistence mechanisms detected", "No persistence mechanisms were identified.")

        report.add_kv("Analysis statistics", {
            "Total API calls": str(len(result.calls)),
            "Processes": str(len(result.processes)),
            "Duration": f"{result.duration:.1f}s",
            "Categories observed": ", ".join(result.categories().keys()) or "-",
        })

        report.add_ioc_section("Indicators of Compromise")
        return report

    def _narrative(self, result: AnalysisResult) -> str:
        if not result.calls:
            return "No parseable API calls found."
        parts = [
            f"{len(result.calls)} API calls across {len(result.processes)} process(es) over "
            f"{result.duration:.1f}s were analyzed."
        ]
        if result.artifacts:
            names = sorted({a.technique_name for a in result.artifacts})
            parts.append(f"Persistence detected: {'; '.join(names[:5])}.")
        else:
            parts.append("No persistence mechanisms matched the catalogue.")
        parts.append(f"Score {result.score}/100 ({result.severity}).")
        return " ".join(parts)

    def analyze(self, path: str) -> AnalysisResult:
        return self.analyse_bytes(Path(path).read_bytes(), name=Path(path).name, path=str(path))
