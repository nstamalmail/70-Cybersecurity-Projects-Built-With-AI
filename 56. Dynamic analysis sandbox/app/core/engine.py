"""Sandbox orchestration engine.

Two entry points:

* :meth:`Engine.analyze` - ingest an existing telemetry artefact (DAS session,
  CAPE/Cuckoo report, ProcMon CSV) and turn it into a behaviour report.  This is
  the path you use when you already have a detonation result.
* :meth:`Engine.detonate` - run the full VM lifecycle (revert to clean snapshot,
  enforce network isolation, boot, upload, execute, collect, teardown) through a
  hypervisor adapter.  Dry-run is the default; the simulation harness is used
  when no hypervisor is available and its output is always labelled synthetic.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app.config import SETTINGS, cases_dir
from app.core import hypervisor, iocs as iocs_mod, ingest
from app.core.model import BehaviorEvent, Session
from app.reporting import Report

STAGES = ["intake", "static", "provision", "execute", "collect", "teardown", "report"]

PERSISTENCE_KEY_RE = re.compile(
    r"(?i)(currentversion\\run|runonce|policies\\explorer\\run|\\startup\\|"
    r"services\\|winlogon|appinit_dlls|image file execution options|taskcache)"
)
SHADOW_DELETE_RE = re.compile(r"(?i)\b(vssadmin|wbadmin|bcdedit|wmic\s+shadowcopy|diskshadow)\b")
ENCODED_PS_RE = re.compile(r"(?i)(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String)")
ANTI_ANALYSIS_RE = re.compile(
    r"(?i)(isdebuggerpresent|checkremotedebuggerpresent|ntqueryinformationprocess|"
    r"vmware|virtualbox|vboxservice|sbiedll|wireshark|procmon|x64dbg|ollydbg|sleep\()"
)
CREDENTIAL_RE = re.compile(r"(?i)(lsass|sekurlsa|mimikatz|sam\b|ntds\.dit|vault|credential)")
EXFIL_BYTES = 5 * 1024 * 1024

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# --------------------------------------------------------------------------- #
#  signature helpers
# --------------------------------------------------------------------------- #
def _events(session: Session, *types: str) -> list[BehaviorEvent]:
    return session.by_type(*types)


def _match_run_key(session: Session) -> list[str]:
    out = []
    for event in _events(session, "registry_set"):
        if PERSISTENCE_KEY_RE.search(event.path or ""):
            data = event.arguments.get("value_data", "")
            out.append(f"{event.clock()} {event.process_name}: {event.path} = {data}"[:220])
    return out


def _match_service(session: Session) -> list[str]:
    out = []
    for event in _events(session, "service_create"):
        out.append(
            f"{event.clock()} {event.process_name}: service "
            f"{event.arguments.get('service_name', '?')} -> {event.arguments.get('binary_path', '?')}"[:220]
        )
    return out


def _match_task(session: Session) -> list[str]:
    return [
        f"{e.clock()} {e.process_name}: task {e.arguments.get('task_name', '?')} -> "
        f"{e.arguments.get('command', '?')}"[:220]
        for e in _events(session, "task_create")
    ]


def _match_injection(session: Session) -> list[str]:
    out = []
    for event in _events(session, "process_inject"):
        out.append(
            f"{event.clock()} {event.process_name}: {event.function} target pid "
            f"{event.arguments.get('target_pid', '?')}"[:220]
        )
    return out


def _match_credential(session: Session) -> list[str]:
    out = []
    for event in session.events:
        blob = " ".join(
            str(v) for v in (
                event.path, event.function, event.data,
                " ".join(str(v) for v in event.arguments.values()),
            )
        )
        if CREDENTIAL_RE.search(blob):
            out.append(f"{event.clock()} {event.process_name}: {event.label} - {event.summary()}"[:220])
    return out[:12]


def _match_shadow_delete(session: Session) -> list[str]:
    out = []
    for event in session.events:
        blob = " ".join(str(v) for v in event.arguments.values()) + " " + (event.data or "")
        if SHADOW_DELETE_RE.search(blob):
            out.append(f"{event.clock()} {event.process_name}: {blob.strip()[:200]}")
    return out[:8]


def _match_mass_modification(session: Session) -> list[str]:
    writes = _events(session, "file_write", "file_rename", "dropped_file")
    extensions: dict[str, int] = {}
    for event in writes:
        suffix = Path(event.path).suffix.lower()
        if suffix:
            extensions[suffix] = extensions.get(suffix, 0) + 1
    renamed = [e for e in writes if e.event_type == "file_rename"]
    if len(writes) >= 25 or len(renamed) >= 10:
        top = ", ".join(f"{k} x{v}" for k, v in sorted(extensions.items(), key=lambda kv: -kv[1])[:5])
        return [
            f"{len(writes)} file modifications, {len(renamed)} renames in "
            f"{session.duration:.0f}s (extensions: {top})"
        ]
    return []


def _match_dropped_executable(session: Session) -> list[str]:
    out = []
    for event in _events(session, "dropped_file", "file_write"):
        path = event.path or ""
        if re.search(r"(?i)\.(exe|dll|sys|scr|ps1|bat|vbs|js|hta)$", path):
            digest = f" sha256={event.sha256}" if event.sha256 else ""
            out.append(f"{event.clock()} {event.process_name}: {path}{digest}"[:220])
    return out[:15]


def _match_beacon(session: Session) -> list[str]:
    groups: dict[tuple[str, int], list[float]] = {}
    for event in _events(session, "network", "http"):
        if not event.dst_ip:
            continue
        groups.setdefault((event.dst_ip, int(event.dst_port or 443)), []).append(float(event.ts))
    out = []
    for (ip, port), times in groups.items():
        if len(times) < 5:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < 4:
            continue
        mean = statistics.fmean(gaps)
        stdev = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
        cv = stdev / mean if mean else 9.9
        if cv < 0.35:
            out.append(
                f"{ip}:{port} - {len(times)} connections, mean interval {mean:.1f}s, "
                f"jitter {cv * 100:.0f}% (regular check-in)"
            )
    return out[:8]


def _match_dns_anomaly(session: Session) -> list[str]:
    queries = [
        str(e.arguments.get("query") or "").strip().lower()
        for e in _events(session, "dns")
        if e.arguments.get("query")
    ]
    queries = [q for q in queries if q and not q.endswith(".local")]
    if len(queries) < 10:
        return []
    unique = set(queries)
    parent_counts: dict[str, set[str]] = {}
    for query in unique:
        parts = query.split(".")
        if len(parts) >= 3:
            parent_counts.setdefault(".".join(parts[-2:]), set()).add(".".join(parts[:-2]))
    tunnels = [f"{p} ({len(s)} unique subdomains)" for p, s in parent_counts.items() if len(s) >= 8]
    if tunnels or len(unique) / max(1, len(queries)) > 0.8:
        detail = "; ".join(tunnels[:4]) or f"{len(unique)} unique names of {len(queries)} queries"
        return [f"DNS profile suggests DGA or tunnelling: {detail}"]
    return []


def _match_anti_analysis(session: Session) -> list[str]:
    out = []
    for event in _events(session, "api_call", "module_load", "file_read"):
        blob = f"{event.function} {event.path} {event.arguments.get('module', '')}"
        if ANTI_ANALYSIS_RE.search(blob):
            out.append(f"{event.clock()} {event.process_name}: {event.label} - {event.path or ''}"[:200])
    return out[:10]


def _match_encoded_powershell(session: Session) -> list[str]:
    out = []
    for event in session.events:
        blob = " ".join(str(v) for v in event.arguments.values()) + " " + (event.data or "")
        if ENCODED_PS_RE.search(blob):
            out.append(f"{event.clock()} {event.process_name}: {blob.strip()[:200]}")
    return out[:8]


def _match_self_delete(session: Session) -> list[str]:
    out = []
    own = (session.sample_name or "").lower()
    for event in _events(session, "file_delete"):
        if own and own in (event.path or "").lower():
            out.append(f"{event.clock()} {event.process_name}: deleted its own binary {event.path}")
    return out[:5]


def _match_exfiltration(session: Session) -> list[str]:
    out = []
    for event in _events(session, "network", "http"):
        sent = int(event.bytes_sent or 0)
        if sent >= EXFIL_BYTES:
            out.append(
                f"{event.clock()} {event.process_name}: {sent / (1024 * 1024):.1f} MB sent to "
                f"{event.dst_ip}:{event.dst_port}"
            )
    return out[:8]


def _match_startup_folder(session: Session) -> list[str]:
    out = []
    for event in _events(session, "file_write", "dropped_file"):
        if re.search(r"(?i)\\start menu\\programs\\startup\\", event.path or ""):
            out.append(f"{event.clock()} {event.process_name}: {event.path}"[:220])
    return out[:8]


def _match_wmi_subscription(session: Session) -> list[str]:
    out = []
    for event in session.events:
        blob = f"{event.path} {event.data} " + " ".join(str(v) for v in event.arguments.values())
        if re.search(r"(?i)(__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding)", blob):
            out.append(f"{event.clock()} {event.process_name}: {event.label} - {event.summary()}"[:220])
    return out[:6]


SIGNATURES: list[dict] = [
    {
        "id": "beh-runkey", "name": "Autostart registry persistence", "severity": "high",
        "score": 12, "mitre": "T1547.001", "matcher": _match_run_key,
        "why": "Writes a Run/RunOnce-style value so the payload survives reboot.",
    },
    {
        "id": "beh-service", "name": "Service installation", "severity": "high",
        "score": 14, "mitre": "T1543.003", "matcher": _match_service,
        "why": "Installs a Windows service pointing at the payload.",
    },
    {
        "id": "beh-task", "name": "Scheduled task creation", "severity": "high",
        "score": 12, "mitre": "T1053.005", "matcher": _match_task,
        "why": "Creates a scheduled task for execution or persistence.",
    },
    {
        "id": "beh-injection", "name": "Process injection", "severity": "critical",
        "score": 18, "mitre": "T1055", "matcher": _match_injection,
        "why": "Remote thread / APC style injection into another process.",
    },
    {
        "id": "beh-credential", "name": "Credential access", "severity": "critical",
        "score": 18, "mitre": "T1003", "matcher": _match_credential,
        "why": "Touches lsass/SAM/credential stores or vault APIs.",
    },
    {
        "id": "beh-shadow", "name": "Recovery inhibition (shadow copy deletion)", "severity": "critical",
        "score": 16, "mitre": "T1490", "matcher": _match_shadow_delete,
        "why": "Deletes backup/shadow copies - a hallmark of ransomware staging.",
    },
    {
        "id": "beh-mass-modify", "name": "Mass file modification / rename", "severity": "critical",
        "score": 18, "mitre": "T1486", "matcher": _match_mass_modification,
        "why": "Bulk writes and renames consistent with encryption.",
    },
    {
        "id": "beh-dropped-exe", "name": "Dropped executable payload", "severity": "high",
        "score": 10, "mitre": "T1105", "matcher": _match_dropped_executable,
        "why": "Writes an executable/script payload to disk (often to a user-writable path).",
    },
    {
        "id": "beh-beacon", "name": "Periodic C2 check-in", "severity": "high",
        "score": 12, "mitre": "T1071", "matcher": _match_beacon,
        "why": "Regularly spaced connections to the same endpoint (beaconing).",
    },
    {
        "id": "beh-dns", "name": "DGA / DNS tunnelling profile", "severity": "medium",
        "score": 8, "mitre": "T1568.002", "matcher": _match_dns_anomaly,
        "why": "High-cardinality or high-entropy DNS queries.",
    },
    {
        "id": "beh-anti-analysis", "name": "Anti-analysis / anti-VM checks", "severity": "medium",
        "score": 8, "mitre": "T1497", "matcher": _match_anti_analysis,
        "why": "Debugger, sandbox or hypervisor detection.",
    },
    {
        "id": "beh-encoded-ps", "name": "Encoded PowerShell", "severity": "high",
        "score": 10, "mitre": "T1059.001", "matcher": _match_encoded_powershell,
        "why": "Base64-encoded PowerShell command line.",
    },
    {
        "id": "beh-self-delete", "name": "Self-deletion", "severity": "medium",
        "score": 6, "mitre": "T1070.004", "matcher": _match_self_delete,
        "why": "Removes its own binary to hinder response.",
    },
    {
        "id": "beh-exfil", "name": "Large outbound transfer (possible exfiltration)", "severity": "high",
        "score": 10, "mitre": "T1041", "matcher": _match_exfiltration,
        "why": "Sends a large volume of data to a remote endpoint.",
    },
    {
        "id": "beh-startup-folder", "name": "Startup folder persistence", "severity": "high",
        "score": 10, "mitre": "T1547.001", "matcher": _match_startup_folder,
        "why": "Places a payload in the per-user or all-users Startup folder.",
    },
    {
        "id": "beh-wmi", "name": "WMI event subscription", "severity": "high",
        "score": 12, "mitre": "T1546.003", "matcher": _match_wmi_subscription,
        "why": "Creates a WMI filter/consumer for fileless persistence.",
    },
]


def run_signatures(session: Session) -> list[dict]:
    matched: list[dict] = []
    for spec in SIGNATURES:
        try:
            evidence = spec["matcher"](session)
        except Exception:
            evidence = []
        if not evidence:
            continue
        matched.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "severity": spec["severity"],
                "score": spec["score"],
                "mitre": spec["mitre"],
                "why": spec["why"],
                "evidence": evidence,
                "evidence_count": len(evidence),
            }
        )
    matched.sort(key=lambda m: (SEVERITY_ORDER.get(m["severity"], 9), -m["score"]))
    return matched


def severity_from_score(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# --------------------------------------------------------------------------- #
#  result
# --------------------------------------------------------------------------- #
@dataclass
class DetonationResult:
    session: Session
    signatures: list[dict] = field(default_factory=list)
    score: int = 0
    severity: str = "info"
    iocs: list[dict] = field(default_factory=list)
    duration: float = 0.0
    warnings: list[str] = field(default_factory=list)
    vm: dict = field(default_factory=dict)
    lifecycle: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    options: dict = field(default_factory=dict)
    report: Report | None = None

    def summary_rows(self) -> list[tuple[str, str]]:
        s = self.session
        rows = [
            ("artefact", s.sample_name or s.session_id),
            ("source format", s.source),
            ("session id", s.session_id),
            ("sha256", s.sha256 or "(not provided)"),
            ("duration", f"{self.duration:.2f}s"),
            ("run length", f"{s.duration:.1f}s of behaviour"),
            ("events", str(len(s.events))),
            ("processes", str(len(s.processes))),
            ("event types", str(len(s.counters))),
            ("signatures", f"{len(self.signatures)} matched"),
            ("iocs", str(len(self.iocs))),
            ("vm back end", self.vm.get("adapter", "n/a")),
            ("SEVERITY", f"{self.severity.upper()} (score {self.score}/100)"),
            ("report sections", str(len(self.report.sections) if self.report else 0)),
        ]
        if s.simulation:
            rows.insert(0, ("NOTE", "SIMULATED telemetry - not a real detonation"))
        return rows

    # convenience accessors used by the views
    def api_events(self) -> list[BehaviorEvent]:
        return self.session.by_type("api_call")

    def file_events(self) -> list[BehaviorEvent]:
        return self.session.by_type(
            "file_write", "file_read", "file_delete", "file_rename", "dropped_file"
        )

    def registry_events(self) -> list[BehaviorEvent]:
        return self.session.by_type("registry_set", "registry_delete")

    def network_events(self) -> list[BehaviorEvent]:
        return self.session.by_type("network", "dns", "http")

    def persistence_events(self) -> list[BehaviorEvent]:
        return self.session.by_type("service_create", "task_create")


class Engine:
    """Sandbox orchestration + telemetry analysis."""

    def __init__(self, settings=None, bus=None) -> None:
        self.settings = settings or SETTINGS
        self.bus = bus

    # -------------------------------------------------------------- logging
    def _log(self, message: str, level: str = "info") -> None:
        if self.bus:
            self.bus.log(message, level)

    def _progress(self, progress, stage: str, done: int = 0, total: int = 0) -> None:
        if progress:
            progress(stage, done, total)

    # ---------------------------------------------------------------- ingest
    def analyze(self, path: str | Path, *, progress=None, write_artifacts: bool = True) -> DetonationResult:
        started = time.perf_counter()
        self._progress(progress, "intake")
        session = ingest.ingest(
            path,
            bus=self.bus,
            max_events=int(self.settings.get("max_events", 500000)),
        )
        self._progress(progress, "collect")
        result = self._score(session)
        result.options = {
            "mode": "ingest",
            "source": session.source,
            "max_events": int(self.settings.get("max_events", 500000)),
        }
        result.vm = {"adapter": "none (ingested telemetry)", "snapshot": session.snapshot}
        result.duration = time.perf_counter() - started
        if write_artifacts:
            self._write_artifacts(result)
        result.report = self.build_report(result)
        self._progress(progress, "report")
        self._log(
            f"Ingested {len(session.events)} events from {Path(path).name} \u2192 "
            f"{result.severity.upper()} (score {result.score})",
            "success",
        )
        return result

    # -------------------------------------------------------------- detonate
    def detonate(
        self,
        sample_path: str | Path,
        *,
        progress=None,
        dry_run: bool = True,
        collect=None,
        options: dict | None = None,
        write_artifacts: bool = True,
    ) -> DetonationResult:
        """Run the full lifecycle against the selected hypervisor back end."""
        started = time.perf_counter()
        sample = Path(sample_path)
        vm_name = str(self.settings.get("vm_name", "win10-analysis"))
        snapshot = str(self.settings.get("snapshot", "clean-baseline"))
        timeout = int(self.settings.get("analysis_timeout_s", 120))

        self._progress(progress, "intake")
        if not sample.exists():
            raise FileNotFoundError(f"No such sample: {sample}")
        from app.core.hashing import compute_hashes

        hashes = compute_hashes(sample)
        self._log(f"Submitting {sample.name} ({hashes['sha256'][:16]}\u2026) to {vm_name}")

        self._progress(progress, "static")
        adapter = hypervisor.detect(self.settings, self.bus, dry_run=dry_run)
        status = adapter.status(vm_name)
        self._log(f"Hypervisor back end: {adapter.name} ({adapter.reason()})")
        self._log(f"Isolation: {adapter.isolation_note}", "warn")

        lifecycle: list[str] = []
        self._progress(progress, "provision")
        lifecycle.append(f"snapshot revert -> {snapshot}")
        adapter.revert(vm_name, snapshot)
        lifecycle.append("network isolation (--nic1 null / no netdev, no shared folders)")
        adapter.isolate_network(vm_name)
        lifecycle.append(f"boot headless (timeout {timeout}s)")
        adapter.start(vm_name, headless=True)

        self._progress(progress, "execute")
        lifecycle.append("upload guest agent + analyzer, then execute the sample")
        session: Session | None = None
        if collect is not None:
            session = collect(
                {
                    "sample": sample,
                    "hashes": hashes,
                    "adapter": adapter,
                    "timeout": timeout,
                    "bus": self.bus,
                }
            )
            self._log("Guest telemetry collected")
        else:
            self._log(
                "No collector supplied: no guest telemetry was collected. "
                "Provide a guest-agent collector or use the simulation harness.",
                "warn",
            )

        self._progress(progress, "collect")
        lifecycle.append("collect behaviour log, PCAP and dropped files (hash verified)")

        self._progress(progress, "teardown")
        lifecycle.append("power off and revert to the clean snapshot")
        adapter.stop(vm_name, force=True)
        adapter.revert(vm_name, snapshot)

        if session is None:
            session = Session(
                session_id=f"das-{_dt.datetime.now():%Y%m%d-%H%M%S}",
                sample_name=sample.name,
                sample_path=str(sample),
                sha256=hashes["sha256"],
                md5=hashes["md5"],
                started_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                vm_name=vm_name,
                snapshot=snapshot,
                network_mode=str(self.settings.get("network_mode", "simulated")),
                warnings=["No telemetry was collected from the guest agent."],
            )
        session.sha256 = session.sha256 or hashes["sha256"]
        session.md5 = session.md5 or hashes["md5"]
        session.sample_name = session.sample_name or sample.name
        session.vm_name = vm_name
        session.snapshot = snapshot
        session.network_mode = str(self.settings.get("network_mode", "simulated"))

        result = self._score(session)
        result.lifecycle = lifecycle
        result.options = {
            "mode": "detonate",
            "dry_run": dry_run,
            "timeout_s": timeout,
            "hypervisor": adapter.name,
            "network_mode": session.network_mode,
            **(options or {}),
        }
        result.vm = {
            "adapter": adapter.name,
            "reason": adapter.reason(),
            "state": status.state,
            "vm_name": vm_name,
            "snapshot": snapshot,
            "memory_mb": status.memory_mb,
            "cpus": status.cpus,
            "dry_run": dry_run,
            "commands": [c.label() for c in adapter.history],
        }
        result.duration = time.perf_counter() - started
        if write_artifacts:
            self._write_artifacts(result)
        result.report = self.build_report(result)
        self._progress(progress, "report")
        self._log(
            f"Detonation workflow complete \u2192 {result.severity.upper()} "
            f"(score {result.score}), {len(session.events)} events",
            "success",
        )
        return result

    # --------------------------------------------------------------- scoring
    def _score(self, session: Session) -> DetonationResult:
        signatures = run_signatures(session)
        score = min(100, sum(int(s["score"]) for s in signatures))
        severity = severity_from_score(score)
        iocs = iocs_mod.extract(session)
        result = DetonationResult(
            session=session,
            signatures=signatures,
            score=score,
            severity=severity,
            iocs=iocs,
            warnings=list(session.warnings),
        )
        if session.simulation:
            result.warnings.append(
                "SIMULATED TELEMETRY: this run was produced by the built-in harness, "
                "not by a real guest VM. Findings demonstrate the pipeline, not a real sample."
            )
        if not session.events:
            result.warnings.append("The session contains no behaviour events.")
        return result

    # ------------------------------------------------------------- artefacts
    def _write_artifacts(self, result: DetonationResult) -> None:
        try:
            case_dir = cases_dir() / result.session.session_id
            case_dir.mkdir(parents=True, exist_ok=True)
            with (case_dir / "behavior.jsonl").open("w", encoding="utf-8") as fh:
                for event in result.session.events:
                    fh.write(json.dumps(event.to_dict()) + "\n")
            (case_dir / "session.json").write_text(
                json.dumps(
                    {
                        "session": {
                            "session_id": result.session.session_id,
                            "sample_name": result.session.sample_name,
                            "sha256": result.session.sha256,
                            "source": result.session.source,
                            "duration": result.session.duration,
                            "vm_name": result.session.vm_name,
                            "snapshot": result.session.snapshot,
                            "network_mode": result.session.network_mode,
                            "simulation": result.session.simulation,
                        },
                        "counters": result.session.counters,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (case_dir / "processes.json").write_text(
                json.dumps([p.to_dict() for p in result.session.processes], indent=2),
                encoding="utf-8",
            )
            (case_dir / "signatures.json").write_text(
                json.dumps(result.signatures, indent=2), encoding="utf-8"
            )
            (case_dir / "iocs.json").write_text(
                json.dumps(result.iocs, indent=2), encoding="utf-8"
            )
            (case_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "session_id": result.session.session_id,
                        "analysed_at": _dt.datetime.now().isoformat(timespec="seconds"),
                        "score": result.score,
                        "severity": result.severity,
                        "options": result.options,
                        "vm": result.vm,
                        "lifecycle": result.lifecycle,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            result.artifacts = [str(p) for p in sorted(case_dir.glob("*"))]
        except Exception as exc:
            self._log(f"Could not write case artefacts: {exc}", "warn")

    # ---------------------------------------------------------------- report
    def build_report(self, result: DetonationResult) -> Report:
        session = result.session
        report = Report(
            title=f"Dynamic Behaviour Report \u2014 {session.sample_name or session.session_id}",
            subtitle="Sandbox telemetry \u00b7 API calls \u00b7 process tree \u00b7 file system \u00b7 registry \u00b7 network",
            verdict=result.severity.upper(),
            risk_score=result.score,
            summary=self._summary_text(result),
            run_id=session.session_id,
            artifacts=list(result.artifacts),
            iocs=list(result.iocs),
        )
        report.meta = {
            "Sample": session.sample_name,
            "Session id": session.session_id,
            "Telemetry source": session.source,
            "SHA-256": session.sha256 or "(not provided)",
            "MD5": session.md5 or "(not provided)",
            "Run length": f"{session.duration:.1f}s",
            "Events": len(session.events),
            "Processes": len(session.processes),
            "VM": session.vm_name or "(none)",
            "Snapshot": session.snapshot or "(none)",
            "Network mode": session.network_mode or "(unknown)",
            "Hypervisor back end": result.vm.get("adapter", "n/a"),
            "Telemetry": "SIMULATED (harness)" if session.simulation else "captured",
            "Analyst": self.settings.get("analyst", "analyst"),
        }
        if result.warnings:
            report.add_list("Warnings & caveats", result.warnings)
        if result.lifecycle:
            report.add_list("Detonation lifecycle", result.lifecycle)
        if result.vm.get("commands"):
            report.add_list("Hypervisor commands issued", result.vm["commands"])

        # ---- processes
        if session.processes:
            report.add_table(
                "Processes",
                ["PID", "Parent", "Name", "Path", "Command line", "First seen", "Last seen"],
                [
                    [
                        p.pid, p.parent_pid if p.parent_pid is not None else "-", p.name,
                        p.path, p.command_line[:160], f"{p.first_seen:.2f}s", f"{p.last_seen:.2f}s",
                    ]
                    for p in sorted(session.processes, key=lambda p: p.pid)
                ],
            )

        # ---- signatures
        if result.signatures:
            report.add_table(
                "Behaviour signatures triggered",
                ["Severity", "Signature", "Score", "MITRE", "Evidence", "Why it matters"],
                [
                    [s["severity"], s["name"], s["score"], s["mitre"], s["evidence_count"], s["why"]]
                    for s in result.signatures
                ],
                note="Weighted behaviour score is the sum of matched signature scores, clamped to 100.",
            )
            for signature in result.signatures:
                report.add_list(
                    f"Evidence \u2014 {signature['name']} ({signature['mitre']})",
                    signature["evidence"],
                )

        # ---- counters & timeline
        if session.counters:
            report.add_table(
                "Event counters",
                ["Event type", "Count"],
                [[k, v] for k, v in sorted(session.counters.items(), key=lambda kv: -kv[1])],
            )
        bounds = self._timeline_bounds(session)
        if bounds:
            report.add_table(
                "Timeline bounds",
                ["Event type", "First seen", "Last seen", "Count"],
                bounds,
            )

        # ---- api calls
        api_events = result.api_events()
        if api_events:
            top: dict[str, int] = {}
            for event in api_events:
                key = f"{event.dll}!{event.function}" if event.dll else event.function
                top[key] = top.get(key, 0) + 1
            report.add_table(
                "Most frequent API calls",
                ["API", "Calls"],
                [[k, v] for k, v in sorted(top.items(), key=lambda kv: -kv[1])[:40]],
            )
            interesting = [
                e for e in api_events
                if re.search(
                    r"(?i)(reg(set|create|delete)|createservice|createprocess|createremotethread|"
                    r"virtualalloc|writeprocessmemory|internetopen|internetconnect|httpsendrequest|"
                    r"urldownload|writefile|deletefile|cryp|bcrypt|shellexecute|winexec|schrpc|"
                    r"createfile|loadlibrary|getprocaddress)",
                    e.function or "",
                )
            ]
            if interesting:
                report.add_table(
                    "High-value API calls",
                    ["Time", "Process", "DLL", "Function", "Arguments", "Result"],
                    [
                        [
                            e.clock(), e.process_name, e.dll, e.function,
                            json.dumps(e.arguments, default=str)[:300], e.return_value or e.status,
                        ]
                        for e in interesting[:300]
                    ],
                )

        # ---- filesystem / registry / network
        files = result.file_events()
        if files:
            report.add_table(
                "File system activity",
                ["Time", "Process", "Event", "Path", "SHA-256"],
                [
                    [e.clock(), e.process_name, e.event_type, e.path, e.sha256]
                    for e in files[:400]
                ],
            )
        dropped = [e for e in files if e.event_type == "dropped_file" and e.path]
        if dropped:
            report.add_table(
                "Dropped files",
                ["Time", "Process", "Path", "SHA-256"],
                [[e.clock(), e.process_name, e.path, e.sha256] for e in dropped[:150]],
            )
        registry = result.registry_events()
        if registry:
            report.add_table(
                "Registry activity",
                ["Time", "Process", "Event", "Key", "Value", "Data"],
                [
                    [
                        e.clock(), e.process_name, e.event_type, e.path,
                        str(e.arguments.get("value_name", "")),
                        str(e.arguments.get("value_data", ""))[:200],
                    ]
                    for e in registry[:400]
                ],
            )
        persistence = result.persistence_events()
        if persistence:
            report.add_table(
                "Persistence artefacts",
                ["Time", "Process", "Type", "Name", "Target"],
                [
                    [
                        e.clock(), e.process_name, e.event_type,
                        str(e.arguments.get("service_name") or e.arguments.get("task_name") or ""),
                        str(e.arguments.get("binary_path") or e.arguments.get("command") or "")[:200],
                    ]
                    for e in persistence
                ],
            )
        network = [e for e in session.by_type("network", "http") if e.dst_ip]
        if network:
            report.add_table(
                "Network connections",
                ["Time", "Process", "Destination", "Port", "Protocol", "Bytes sent", "Bytes received"],
                [
                    [
                        e.clock(), e.process_name, e.dst_ip, e.dst_port, e.protocol,
                        e.bytes_sent, e.bytes_received,
                    ]
                    for e in network[:400]
                ],
            )
        dns = session.by_type("dns")
        if dns:
            report.add_table(
                "DNS queries",
                ["Time", "Process", "Query", "Answer"],
                [
                    [e.clock(), e.process_name, str(e.arguments.get("query", "")), e.dst_ip]
                    for e in dns[:300]
                ],
            )

        report.add_ioc_section()
        if result.iocs:
            report.add_table(
                "IOC count by type",
                ["Type", "Count"],
                [[t, c] for t, c in iocs_mod.stats(result.iocs)],
            )
        report.add_kv("Run options", result.options)
        return report

    def _timeline_bounds(self, session: Session) -> list[list]:
        bounds: dict[str, list[float]] = {}
        for event in session.events:
            entry = bounds.setdefault(event.event_type, [float(event.ts), float(event.ts), 0.0])
            entry[0] = min(entry[0], float(event.ts))
            entry[1] = max(entry[1], float(event.ts))
            entry[2] += 1
        return [
            [kind, f"{lo:.2f}s", f"{hi:.2f}s", int(count)]
            for kind, (lo, hi, count) in sorted(bounds.items(), key=lambda kv: kv[1][0])
        ]

    def _summary_text(self, result: DetonationResult) -> str:
        session = result.session
        bits = [
            f"{len(session.events)} behaviour events across {len(session.processes)} processes "
            f"were analysed over {session.duration:.1f}s of activity."
        ]
        if result.signatures:
            names = ", ".join(s["name"] for s in result.signatures[:4])
            bits.append(
                f"{len(result.signatures)} behaviour signatures matched (severity "
                f"{result.severity.upper()}, weighted score {result.score}/100): {names}."
            )
        else:
            bits.append(
                f"No behaviour signatures matched - weighted score {result.score}/100 "
                f"({result.severity.upper()})."
            )
        bits.append(
            f"Extracted {len(result.iocs)} indicators covering "
            + ", ".join(f"{t} x{c}" for t, c in iocs_mod.stats(result.iocs)[:6])
            + "."
        )
        if session.simulation:
            bits.append(
                "NOTE: telemetry was produced by the simulation harness and does not "
                "describe a real detonation."
            )
        return " ".join(bits)


def _uuid() -> str:
    return uuid.uuid4().hex[:8]
