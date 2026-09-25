"""Behavioural sequence pattern engine (architecture §3.4).

Patterns describe *ordered* API behaviour rather than single calls, because
``OpenProcess`` on its own is noise while ``OpenProcess -> VirtualAllocEx ->
WriteProcessMemory -> CreateRemoteThread`` is an injection.  A pattern is a list
of steps matched in order inside one process, with a bounded gap so unrelated
calls in between do not break the match.

Each step matches an API name by glob (``*VirtualAlloc*``), optionally restricted
to a category, and the whole match must complete within ``max_span`` seconds so
that two unrelated halves of a long analysis never join into a false positive.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from app.core.model import ApiCall, PatternMatch

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Step:
    """One step of a behavioural pattern."""

    glob: str
    category: str = ""

    def matches(self, call: ApiCall) -> bool:
        if self.category and call.category != self.category:
            return False
        return fnmatch.fnmatch(call.api.lower(), self.glob.lower())


@dataclass(frozen=True)
class SequencePattern:
    pattern_id: str
    name: str
    severity: str
    steps: tuple[Step, ...]
    description: str = ""
    references: tuple[str, ...] = ()
    gap: int = 3
    max_span: float = 300.0
    min_steps: int = 0
    target_step: int = -1
    target_args: tuple[str, ...] = ()
    tags: tuple[str, ...] = field(default_factory=tuple)


def _p(pattern_id, name, severity, description, steps, *, references=(), gap=3, max_span=300.0, target_step=-1, target_args=(), tags=()):
    parsed: list[Step] = []
    for step in steps:
        if isinstance(step, Step):
            parsed.append(step)
        elif isinstance(step, tuple):
            parsed.append(Step(*step))
        else:
            parsed.append(Step(str(step)))
    return SequencePattern(
        pattern_id=pattern_id,
        name=name,
        severity=severity,
        steps=tuple(parsed),
        description=description,
        references=tuple(references),
        gap=gap,
        max_span=max_span,
        min_steps=len(parsed),
        target_step=target_step,
        target_args=tuple(target_args),
        tags=tuple(tags),
    )


# --------------------------------------------------------------------------- #
#  Pattern catalogue
# --------------------------------------------------------------------------- #
OUT = "T1055 - Process Injection"
PERSIST = "T1547/T1543 - Persistence"
EXEC = "T1059/T1106 - Execution"
CRED = "T1003 - Credential Access"
RANSOM = "T1486 - Data Encrypted for Impact"
DEFENSE = "T1562 - Impair Defenses"
DISCOVERY = "T1046/T1082 - Discovery"
EXFIL = "T1041 - Exfiltration Over C2"

PATTERNS: tuple[SequencePattern, ...] = (
    _p(
        "INJ-001",
        "Classic remote process injection",
        "critical",
        "A handle is opened on a foreign process, memory is allocated inside it, "
        "shellcode is written and a remote thread starts the payload - the canonical "
        "injection chain.",
        [("openprocess",), ("virtualallocex", "memory"), ("writeprocessmemory", "memory"), ("createremotethread",)],
        references=(OUT,),
        target_step=0,
        target_args=("process_identifier", "process_name", "processid"),
        tags=("injection",),
    ),
    _p(
        "INJ-002",
        "Section mapping injection",
        "critical",
        "Memory is allocated in the target and a section view is mapped, which lets the "
        "loader avoid WriteProcessMemory on the injected buffer.",
        [("ntallocatevirtualmemory", "memory"), ("ntmapviewofsection", "memory"), ("resumethread",)],
        references=(OUT,),
        target_step=0,
        target_args=("process_identifier", "process_name"),
        tags=("injection",),
    ),
    _p(
        "INJ-003",
        "APC / thread context injection",
        "high",
        "Queues an APC or rewrites a thread context so the payload runs inside the target "
        "when its thread next resumes.",
        [("openprocess",), ("queueuserapc",), ("*processmemory*", "memory")],
        references=(OUT,),
        gap=4,
        target_step=0,
        target_args=("process_identifier", "process_name"),
        tags=("injection",),
    ),
    _p(
        "INJ-004",
        "Hollowed remote process",
        "critical",
        "A suspended foreign process is created, its memory unmapped and reallocated, and it "
        "is resumed with attacker code (process hollowing).",
        [("createprocess*", "process"), ("*unmapview*", "memory"), ("virtualalloc*", "memory"), ("*setthreadcontext*",)],
        references=("T1055.012 - Process Hollowing",),
        gap=5,
        target_step=0,
        target_args=("application_name", "command_line", "module_name"),
        tags=("injection",),
    ),
    _p(
        "INJ-005",
        "Debug API based injection",
        "high",
        "Attaches a debugger to a foreign process to control its threads - used to inject and to "
        "evade userland hooks.",
        [("debugactiveprocess*",), ("*threadcontext*",), ("*writeprocessmemory*", "memory")],
        references=(OUT,),
        gap=6,
        tags=("injection",),
    ),
    _p(
        "PERS-001",
        "Run key persistence",
        "high",
        "Writes a value under a Run key so the payload executes at logon.",
        [("*regcreatekey*", "registry"), ("*regsetvalue*", "registry"), ("*file*", "file")],
        references=(PERSIST,),
        gap=8,
        max_span=120.0,
        target_step=1,
        target_args=("regkey", "key_handle", "subkey", "value_name"),
        tags=("persistence",),
    ),
    _p(
        "PERS-002",
        "New service installed",
        "critical",
        "Creates and starts a Windows service pointing at the dropped payload (also the "
        "behaviour of the DoublePulsar/SMB delivery chain).",
        [("*openscmanager*", "system"), ("*createservice*", "system"), ("*startservice*", "system")],
        references=("T1543.003 - Windows Service",),
        gap=6,
        target_step=1,
        target_args=("service_name", "display_name", "binary_path"),
        tags=("persistence",),
    ),
    _p(
        "PERS-003",
        "Startup folder drop",
        "high",
        "Writes a file into a Startup or StartupCommon directory.",
        [("*directory*", "file"), ("*file*", "file"), ("*file*", "file")],
        references=(PERSIST,),
        gap=10,
        target_step=1,
        target_args=("file_name", "filename", "filepath"),
        tags=("persistence",),
    ),
    _p(
        "PERS-004",
        "Persistence via directory creation",
        "medium",
        "Creates a directory and immediately stores a file in it, typical of a persistent "
        "staging folder.",
        [("*createdirectory*", "file"), ("*createfile*", "file"), ("*writefile*", "file")],
        gap=4,
        tags=("persistence", "dropper"),
    ),
    _p(
        "EXEC-001",
        "Dropped file executed",
        "high",
        "A file is written to disk and then executed by name or through a shell call "
        "(dropper / download-and-execute).",
        [("*writefile*", "file"), ("*closehandle*",), ("*createprocess*", "process")],
        references=(EXEC,),
        gap=12,
        max_span=180.0,
        target_step=0,
        target_args=("file_name", "filename", "filepath"),
        tags=("execution", "dropper"),
    ),
    _p(
        "EXEC-002",
        "Shell execution",
        "high",
        "ShellExecutes or Winexecs a command line rather than using a raw process create.",
        [("*shellexecute*",), ("*createprocess*", "process")],
        references=(EXEC,),
        gap=6,
        target_step=0,
        target_args=("filepath", "file_name", "command_line", "parameters"),
        tags=("execution",),
    ),
    _p(
        "EXEC-003",
        "Script interpreter launched",
        "high",
        "Starts a scripting host (PowerShell, cmd, wscript, mshta, rundll32) - the standard "
        "living-off-the-land execution path.",
        [("*createprocess*", "process"), ("*file*", "file")],
        references=(EXEC, "T1218 - System Binary Proxy Execution"),
        gap=4,
        target_step=0,
        target_args=("application_name", "command_line", "file_name"),
        tags=("execution", "living-off-the-land"),
    ),
    _p(
        "NET-001",
        "Download and execute",
        "critical",
        "A remote payload is fetched over HTTP, written to disk and executed.",
        [("*internetreadfile*",), ("*writefile*", "file"), ("*createprocess*", "process")],
        references=("T1105 - Ingress Tool Transfer", EXEC),
        gap=10,
        max_span=300.0,
        target_step=0,
        target_args=("url", "uri", "object_name"),
        tags=("network", "dropper"),
    ),
    _p(
        "NET-002",
        "Network beacon setup",
        "high",
        "Resolves a host and opens a socket, the first stage of command-and-control "
        "initialisation.",
        [("*gethostbyname*", "network"), ("*connect*", "network"), ("*send*", "network")],
        references=("T1071 - Application Layer Protocol",),
        gap=8,
        target_step=0,
        target_args=("hostname", "host_name", "name"),
        tags=("network", "c2"),
    ),
    _p(
        "NET-003",
        "Repeated socket send burst",
        "medium",
        "Many send calls on the same connection - bulk upload or exfiltration traffic.",
        [("*send*", "network"), ("*send*", "network"), ("*send*", "network"), ("*send*", "network")],
        references=(EXFIL,),
        gap=1,
        max_span=60.0,
        tags=("network", "exfiltration"),
    ),
    _p(
        "CRED-001",
        "Credential store access",
        "critical",
        "Opens the memory of a credential process (lsass) and reads it - direct credential "
        "dumping.",
        [("openprocess",), ("*readprocessmemory*", "memory"), ("*memory*", "memory")],
        references=(CRED,),
        gap=6,
        target_step=0,
        target_args=("process_identifier", "process_name"),
        tags=("credential-access",),
    ),
    _p(
        "CRED-002",
        "Credential file staging",
        "high",
        "Reads a browser/host credential store and immediately writes a copy out - the "
        "stealer pattern.",
        [("*createfile*", "file"), ("*readfile*", "file"), ("*writefile*", "file"), ("*file*", "file")],
        references=(CRED,),
        gap=8,
        max_span=120.0,
        target_step=0,
        target_args=("file_name", "filename", "filepath"),
        tags=("credential-access", "stealer"),
    ),
    _p(
        "RANS-001",
        "Shadow copy destruction",
        "critical",
        "Enumerates and deletes volume shadow copies to prevent recovery before encryption.",
        [("*directory*", "file"), ("*createprocess*", "process"), ("*process*", "process")],
        references=(RANSOM, "T1490 - Inhibit System Recovery"),
        gap=8,
        max_span=180.0,
        target_step=1,
        target_args=("application_name", "command_line"),
        tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-002",
        "Encrypt in place",
        "critical",
        "Reads a file, encrypts the buffer and rewrites it in place, repeatedly - the "
        "file-encryption loop.",
        [("*readfile*", "file"), ("*cryptencrypt*", "crypto"), ("*writefile*", "file")],
        references=(RANSOM,),
        gap=6,
        max_span=60.0,
        target_step=0,
        target_args=("file_name", "filename", "filepath", "handle"),
        tags=("ransomware", "impact"),
    ),
    _p(
        "RANS-003",
        "Bulk file enumeration and rename",
        "high",
        "Walks the filesystem and renames matching files - the extension-swap phase of a "
        "ransomware run.",
        [("*findfirstfile*", "file"), ("*findnextfile*", "file"), ("*movefile*", "file")],
        references=(RANSOM,),
        gap=12,
        max_span=120.0,
        tags=("ransomware", "impact"),
    ),
    _p(
        "DEF-001",
        "Anti-debug checks",
        "medium",
        "Runs debugger-presence checks early, which usually precedes evasion setup.",
        [("*isdebuggerpresent*",), ("*checkremotedebugger*",)],
        references=(DEFENSE,),
        gap=10,
        tags=("evasion",),
    ),
    _p(
        "DEF-002",
        "Security stack tampering",
        "critical",
        "Touches enable/disable values under the Windows Defender policy keys.",
        [("*regcreatekey*", "registry"), ("*regsetvalue*", "registry"), ("*regsetvalue*", "registry")],
        references=(DEFENSE,),
        gap=6,
        target_step=1,
        target_args=("regkey", "subkey", "value_name"),
        tags=("evasion", "defense-evasion"),
    ),
    _p(
        "DEF-003",
        "Environment fingerprinting",
        "medium",
        "Collects host and firmware identifiers in a burst - sandbox and victim profiling.",
        [("*getsysteminfo*",), ("*getcomputername*",), ("*getvolumeinformation*",)],
        references=(DISCOVERY,),
        gap=10,
        tags=("discovery",),
    ),
    _p(
        "DISC-001",
        "Process enumeration",
        "medium",
        "Walks the process list, typically looking for security tooling or an injection "
        "target.",
        [("*process32first*",), ("*process32next*",), ("*process32next*",)],
        references=(OUT, DISCOVERY),
        gap=2,
        tags=("discovery",),
    ),
    _p(
        "DISC-002",
        "Enumerate and open a target",
        "high",
        "Enumerates processes then immediately opens one - target selection for injection.",
        [("*process32first*",), ("*process32next*",), ("openprocess",)],
        references=(OUT,),
        gap=4,
        target_step=2,
        target_args=("process_identifier", "process_name"),
        tags=("discovery", "injection"),
    ),
    _p(
        "PERS-005",
        "Scheduled task creation",
        "high",
        "Creates or queries a scheduled task pointing at the payload, a common persistence "
        "and privilege path.",
        [("*process*", "process"), ("*file*", "file"), ("*registry*", "registry")],
        references=("T1053.005 - Scheduled Task",),
        gap=10,
        tags=("persistence",),
    ),
    _p(
        "MEM-001",
        "Self-modifying memory",
        "high",
        "Allocates, writes and flips memory protection to executable - unpacking or reflective "
        "loading in the same process.",
        [("*virtualalloc*", "memory"), ("*writeprocessmemory*", "memory"), ("*virtualprotect*", "memory")],
        references=("T1027.002 - Software Packing",),
        gap=6,
        tags=("evasion", "unpacking"),
    ),
    _p(
        "NET-004",
        "DNS resolution burst",
        "medium",
        "Resolves several distinct hostnames in quick succession, consistent with domain "
        "generation or list-based beaconing.",
        [("*gethostbyname*", "network"), ("*gethostbyname*", "network"), ("*gethostbyname*", "network")],
        references=(DISCOVERY,),
        gap=2,
        max_span=30.0,
        tags=("network", "c2"),
    ),
)

PATTERN_INDEX = {pattern.pattern_id: pattern for pattern in PATTERNS}


# --------------------------------------------------------------------------- #
#  Matcher
# --------------------------------------------------------------------------- #
def _target_for(pattern: SequencePattern, matched: list[ApiCall]) -> str:
    if pattern.target_step < 0 or pattern.target_step >= len(matched):
        return ""
    call = matched[pattern.target_step]
    if pattern.target_args:
        value = call.arg(*pattern.target_args, default="")
        if value:
            return value
    for argument in call.arguments:
        if argument.value:
            return argument.value
    return ""


def match_pattern(pattern: SequencePattern, calls: list[ApiCall], *, process_id: int = 0, process_name: str = "") -> list[PatternMatch]:
    """Sliding-window match of one pattern against one process' call list."""
    matches: list[PatternMatch] = []
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
            matches.append(
                PatternMatch(
                    pattern_id=pattern.pattern_id,
                    name=pattern.name,
                    severity=pattern.severity,
                    process_id=process_id,
                    process_name=process_name,
                    start_ts=matched[0].timestamp,
                    end_ts=matched[-1].timestamp,
                    call_ids=[call.call_id for call in matched],
                    apis=[call.api for call in matched],
                    description=pattern.description,
                    references=list(pattern.references),
                    target=_target_for(pattern, matched),
                )
            )
            index = cursor
        else:
            index += 1
    return matches


def match_all(calls: list[ApiCall], *, patterns=PATTERNS, limit: int = 4000) -> list[PatternMatch]:
    """Match every pattern against every process."""
    by_process: dict[int, list[ApiCall]] = {}
    for call in calls:
        by_process.setdefault(call.process_id, []).append(call)

    found: list[PatternMatch] = []
    for process_id, sequence in by_process.items():
        name = sequence[0].process_name
        for pattern in patterns:
            if len(sequence) < len(pattern.steps):
                continue
            found.extend(match_pattern(pattern, sequence, process_id=process_id, process_name=name))
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break

    found.sort(key=lambda match: (match.start_ts, -SEVERITY_ORDER.get(match.severity, 0)))
    return found


# --------------------------------------------------------------------------- #
#  Scoring
# --------------------------------------------------------------------------- #
def score_matches(matches: list[PatternMatch], calls: list[ApiCall], processes: list) -> tuple[int, str]:
    """Behaviour score 0-100 plus the severity band (architecture §3.8)."""
    if not matches:
        base = 0.0
    else:
        weights = {"critical": 26.0, "high": 15.0, "medium": 7.0, "low": 3.0, "info": 1.0}
        tags: set[str] = set()
        for match in matches:
            pattern = PATTERN_INDEX.get(match.pattern_id)
            if pattern is not None:
                tags.update(pattern.tags)
        base = sum(weights.get(match.severity, 3.0) for match in matches)
        if {"injection", "ransomware", "credential-access"} & tags:
            base += 8.0
        if {"persistence", "c2"} & tags:
            base += 5.0
    if calls:
        failures = sum(call.weight for call in calls if call.failed)
        total = sum(call.weight for call in calls)
        base += min(6.0, (failures / total) * 30.0) if total else 0.0
    suspicious_processes = sum(1 for node in processes if getattr(node, "suspicious", False))
    base += min(6.0, suspicious_processes * 2.0)

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
            "pattern_id": pattern.pattern_id,
            "name": pattern.name,
            "severity": pattern.severity,
            "steps": " -> ".join(step.glob for step in pattern.steps),
            "gap": pattern.gap,
            "max_span": pattern.max_span,
            "description": pattern.description,
            "references": list(pattern.references),
            "tags": list(pattern.tags),
        }
        for pattern in PATTERNS
    ]
