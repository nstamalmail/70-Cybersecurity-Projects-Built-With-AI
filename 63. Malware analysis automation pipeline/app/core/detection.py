"""Persistence technique detection patterns (MITRE ATT&CK TA0003)."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from app.core.model import ApiCall, PersistenceArtifact

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Step:
    glob: str
    category: str = ""

    def matches(self, call: ApiCall) -> bool:
        if self.category and call.category != self.category:
            return False
        return fnmatch.fnmatch(call.api.lower(), self.glob.lower())


@dataclass(frozen=True)
class PersistencePattern:
    pattern_id: str
    name: str
    severity: str
    steps: tuple[Step, ...]
    description: str = ""
    references: tuple[str, ...] = ()
    gap: int = 5
    max_span: float = 300.0
    tags: tuple[str, ...] = field(default_factory=tuple)


def _p(pattern_id, name, severity, description, steps, *, references=(), gap=5, max_span=300.0, tags=()):
    parsed = []
    for step in steps:
        if isinstance(step, Step):
            parsed.append(step)
        elif isinstance(step, tuple):
            parsed.append(Step(*step))
        else:
            parsed.append(Step(str(step)))
    return PersistencePattern(
        pattern_id=pattern_id, name=name, severity=severity,
        steps=tuple(parsed), description=description, references=tuple(references),
        gap=gap, max_span=max_span, tags=tuple(tags),
    )


# --- Pattern catalogue (MITRE TA0003) ---
PATTERNS: tuple[PersistencePattern, ...] = (
    _p(
        "PERS-001", "Registry Run Key Persistence", "high",
        "Writes a value under a Run key so the payload executes at logon.",
        [("RegSetValueExW", "registry"), ("CreateFileW", "file")],
        references=("T1547.001",), gap=8, tags=("persistence", "registry"),
    ),
    _p(
        "PERS-002", "Windows Service Installation", "critical",
        "Creates and starts a Windows service pointing at the dropped payload.",
        [("OpenSCManagerW", "system"), ("CreateServiceW", "system"), ("StartServiceW", "system")],
        references=("T1543.003",), gap=6, tags=("persistence", "service"),
    ),
    _p(
        "PERS-003", "Scheduled Task Creation", "high",
        "Creates a scheduled task for persistence and privilege escalation.",
        [("schtasks", "process"), ("CreateFileW", "file")],
        references=("T1053.005",), gap=8, tags=("persistence", "scheduled-task"),
    ),
    _p(
        "PERS-004", "Startup Folder Drop", "high",
        "Writes a file into a Startup directory for automatic execution.",
        [("*file*", "file"), ("*file*", "file"), ("*file*", "file")],
        references=("T1547.001",), gap=10, tags=("persistence", "startup"),
    ),
    _p(
        "PERS-005", "DLL Search Order Hijacking", "medium",
        "Places a DLL in a location searched before legitimate system DLLs.",
        [("CreateFileW", "file"), ("WriteFile", "file"), ("CreateProcessW", "process")],
        references=("T1574.001",), gap=6, tags=("persistence", "hijacking"),
    ),
    _p(
        "PERS-006", "COM Object Hijacking", "high",
        "Redirects COM object loading to execute malicious code.",
        [("RegSetValueExW", "registry"), ("CoCreateInstance", "system")],
        references=("T1546.015",), gap=8, tags=("persistence", "com"),
    ),
    _p(
        "PERS-007", "WMI Event Subscription", "critical",
        "Creates WMI event subscriptions for persistent code execution.",
        [("RegSetValueExW", "registry"), ("CreateProcessW", "process")],
        references=("T1546.003",), gap=6, tags=("persistence", "wmi"),
    ),
    _p(
        "PERS-008", "Bootkit / MBR Modification", "critical",
        "Modifies the Master Boot Record for pre-boot persistence.",
        [("CreateFileW", "file"), ("WriteFile", "file")],
        references=("T1542.003",), gap=4, tags=("persistence", "bootkit"),
    ),
    _p(
        "PERS-009", " BITS Job Persistence", "medium",
        "Creates BITS jobs for background file transfer and persistence.",
        [("CreateProcessW", "process"), ("CreateFileW", "file")],
        references=("T1197",), gap=6, tags=("persistence", "bits"),
    ),
    _p(
        "PERS-010", "Office Application Startup", "medium",
        "Modifies Office settings for persistence via add-ins or templates.",
        [("RegSetValueExW", "registry"), ("CreateFileW", "file")],
        references=("T1137",), gap=8, tags=("persistence", "office"),
    ),
)

PATTERN_INDEX = {pattern.pattern_id: pattern for pattern in PATTERNS}


def match_pattern(pattern: PersistencePattern, calls: list[ApiCall], *, process_id: int = 0, process_name: str = "") -> list[PersistenceArtifact]:
    matches: list[PersistenceArtifact] = []
    size = len(calls)
    index = 0
    while index < size:
        if not pattern.steps[0].matches(calls[index]):
            index += 1
            continue
        cursor = index + 1
        matched = [calls[index]]
        ok = True
        for step in pattern.steps[1:]:
            found = -1
            limit = min(size, cursor + pattern.gap + 1)
            for probe in range(cursor, limit):
                if step.matches(calls[probe]):
                    found = probe
                    break
            if found < 0:
                ok = False
                break
            matched.append(calls[found])
            cursor = found + 1
        if ok and (matched[-1].timestamp - matched[0].timestamp) <= pattern.max_span:
            evidence = [f"{call.api} @ {call.timestamp:.2f}s" for call in matched]
            key_path = ""
            service_name = ""
            for call in matched:
                kp = call.arg("regkey", "subkey", "key_handle", default="")
                if kp and "run" in kp.lower():
                    key_path = kp
                sn = call.arg("service_name", "display_name", default="")
                if sn:
                    service_name = sn
            artifact = PersistenceArtifact(
                technique_id=pattern.pattern_id,
                technique_name=pattern.name,
                severity=pattern.severity,
                source="behavior",
                key_path=key_path,
                service_name=service_name,
                process_id=process_id,
                process_name=process_name,
                timestamp=matched[0].timestamp,
                confidence=0.85,
                evidence=evidence,
                references=list(pattern.references),
            )
            matches.append(artifact)
            index = cursor
        else:
            index += 1
    return matches


def match_all(calls: list[ApiCall], *, limit: int = 2000) -> list[PersistenceArtifact]:
    by_process: dict[int, list[ApiCall]] = {}
    for call in calls:
        by_process.setdefault(call.process_id, []).append(call)
    found: list[PersistenceArtifact] = []
    for process_id, sequence in by_process.items():
        name = sequence[0].process_name
        for pattern in PATTERNS:
            if len(sequence) < len(pattern.steps):
                continue
            found.extend(match_pattern(pattern, sequence, process_id=process_id, process_name=name))
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    found.sort(key=lambda a: (a.timestamp, -SEVERITY_ORDER.get(a.severity, 0)))
    return found


def score_matches(artifacts: list[PersistenceArtifact]) -> tuple[int, str]:
    if not artifacts:
        return 0, "clean"
    weights = {"critical": 26.0, "high": 15.0, "medium": 7.0, "low": 3.0}
    base = sum(weights.get(a.severity, 3.0) for a in artifacts)
    score = int(max(0, min(100, round(base))))
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score >= 15:
        severity = "low"
    else:
        severity = "info"
    return score, severity


def pattern_catalogue() -> list[dict]:
    return [
        {
            "pattern_id": p.pattern_id,
            "name": p.name,
            "severity": p.severity,
            "steps": " -> ".join(step.glob for step in p.steps),
            "gap": p.gap,
            "max_span": p.max_span,
            "description": p.description,
            "references": list(p.references),
            "tags": list(p.tags),
        }
        for p in PATTERNS
    ]
