"""Ransomware encryption pattern detection (five operational stages)."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from app.core.model import ApiCall, PersistenceArtifact

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Ransomware encryption stages
STAGES = ("discovery", "access", "modification", "obfuscation", "destruction")

STAGE_MARKERS = {
    "discovery": ("FindFirstFile*", "FindNextFile*", "GetFileAttributes*"),
    "access": ("CreateFileW",),
    "modification": ("ReadFile", "WriteFile", "CryptEncrypt", "CryptGenKey"),
    "obfuscation": ("MoveFile*", "SetFileAttributes*"),
    "destruction": ("DeleteFile*", "vssadmin*"),
}


@dataclass(frozen=True)
class Step:
    glob: str
    category: str = ""

    def matches(self, call: ApiCall) -> bool:
        if self.category and call.category != self.category:
            return False
        return fnmatch.fnmatch(call.api.lower(), self.glob.lower())


@dataclass(frozen=True)
class EncryptionPattern:
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
    return EncryptionPattern(
        pattern_id=pattern_id, name=name, severity=severity,
        steps=tuple(parsed), description=description, references=tuple(references),
        gap=gap, max_span=max_span, tags=tuple(tags),
    )


PATTERNS: tuple[EncryptionPattern, ...] = (
    _p(
        "RANS-001", "Shadow Copy Destruction", "critical",
        "Enumerates and deletes volume shadow copies before encryption.",
        [("FindFirstFile*", "file"), ("CreateProcessW", "process"), ("DeleteFile*", "file")],
        references=("T1490",), gap=8, tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-002", "In-Place File Encryption", "critical",
        "Reads a file, encrypts the buffer and rewrites it in place.",
        [("ReadFile", "file"), ("CryptEncrypt", "crypto"), ("WriteFile", "file")],
        references=("T1486",), gap=6, max_span=60.0, tags=("ransomware", "encryption"),
    ),
    _p(
        "RANS-003", "Bulk File Enumeration and Rename", "high",
        "Walks the filesystem and renames files with ransomware extensions.",
        [("FindFirstFile*", "file"), ("FindNextFile*", "file"), ("MoveFile*", "file")],
        references=("T1486",), gap=12, max_span=120.0, tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-004", "Ransom Note Drop", "high",
        "Creates and writes a ransom note file.",
        [("CreateFileW", "file"), ("WriteFile", "file")],
        references=("T1486",), gap=4, tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-005", "Recovery Prevention", "critical",
        "Disables Windows recovery and boot configuration.",
        [("CreateProcessW", "process"), ("CreateProcessW", "process")],
        references=("T1490",), gap=6, tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-006", "Mass File Encryption Loop", "critical",
        "Repeats file read-encrypt-write across many files rapidly.",
        [("ReadFile", "file"), ("CryptEncrypt", "crypto"), ("WriteFile", "file")],
        references=("T1486",), gap=4, max_span=120.0, tags=("ransomware", "encryption"),
    ),
)

PATTERN_INDEX = {pattern.pattern_id: pattern for pattern in PATTERNS}


def match_pattern(pattern: EncryptionPattern, calls: list[ApiCall], *, process_id: int = 0, process_name: str = "") -> list[PersistenceArtifact]:
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
            artifact = PersistenceArtifact(
                technique_id=pattern.pattern_id,
                technique_name=pattern.name,
                severity=pattern.severity,
                source="behavior",
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
        {"pattern_id": p.pattern_id, "name": p.name, "severity": p.severity,
         "steps": " -> ".join(step.glob for step in p.steps), "gap": p.gap,
         "max_span": p.max_span, "description": p.description,
         "references": list(p.references), "tags": list(p.tags)}
        for p in PATTERNS
    ]


def classify_stages(calls: list[ApiCall]) -> dict[str, list[ApiCall]]:
    """Classify calls into encryption stages."""
    stages: dict[str, list[ApiCall]] = {stage: [] for stage in STAGES}
    for call in calls:
        api_lower = call.api.lower()
        for stage, markers in STAGE_MARKERS.items():
            for marker in markers:
                if fnmatch.fnmatch(api_lower, marker.lower()):
                    stages[stage].append(call)
                    break
    return stages
