"""Process detection rules.

Design principles (low false-positive rate):
- Each rule returns (rule_id, severity, human reason).
- Conservative matches; noisy combos require multiple signals.
- Cross-platform paths (Windows + POSIX markers).
"""

import re
from typing import List, Tuple

from ..core.models import ProcessInfo

TEMP_MARKERS = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\temp",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\perflogs\\",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
)

OFFICE_SCRIPT_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "wscript.exe",
    "cscript.exe",
}

SHELL_CHILDREN = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

SYSTEM_PROCESS_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
}
WINDOWS_SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")

PWS_SUSPICIOUS = re.compile(
    r"(-enc\b|-encodedcommand\b|-w\s+hidden|-windowstyle\s+hidden|-nop\b|-noni\b)",
    re.IGNORECASE,
)
PERSISTENCE = re.compile(
    r"(currentversion\\run\b|currentversion\\runonce\b|schtasks\s+/create|"
    r"wmic\s+startup|new-service\b)",
    re.IGNORECASE,
)

# (rule_id, severity, matcher) — evaluated in order, all matches reported.
_RULES = []


def rule(rule_id: str, severity: str, description: str):
    def deco(fn):
        _RULES.append((rule_id, severity, description, fn))
        return fn

    return deco


@rule("BLACKLISTED_PROCESS", "CRITICAL", "Known offensive/malicious tool")
def _blacklisted(p: ProcessInfo, ctx) -> bool:
    return p.name.lower() in ctx["blacklist"]


@rule("SUSPICIOUS_POWERSHELL", "CRITICAL", "Encoded/hidden PowerShell arguments")
def _pws_suspicious(p: ProcessInfo, ctx) -> bool:
    if p.name.lower() not in ("powershell.exe", "pwsh.exe"):
        return False
    return bool(PWS_SUSPICIOUS.search(p.cmdline_str))


@rule("OFFICE_SPAWNED_SHELL", "HIGH", "Office/script host spawned a shell")
def _office_shell(p: ProcessInfo, ctx) -> bool:
    parent = (p.parent_name or "").lower()
    return parent in OFFICE_SCRIPT_PARENTS and p.name.lower() in SHELL_CHILDREN


@rule("EXECUTABLE_IN_TEMP", "HIGH", "Executable running from a temp location")
def _temp_exec(p: ProcessInfo, ctx) -> bool:
    exe = (p.exe or "").lower()
    return bool(exe) and any(m in exe for m in TEMP_MARKERS)


@rule("SYSTEM_PROCESS_IMPERSONATION", "HIGH", "System process name outside System32")
def _impersonation(p: ProcessInfo, ctx) -> bool:
    name = p.name.lower()
    exe = (p.exe or "").lower()
    if name not in SYSTEM_PROCESS_NAMES or not exe:
        return False
    if "/" in exe:  # POSIX: rule targets Windows impersonation only
        return False
    return not exe.startswith(WINDOWS_SYSTEM_DIRS)


@rule("PERSISTENCE_ATTEMPT", "HIGH", "Run-key / scheduled-task persistence in cmdline")
def _persistence(p: ProcessInfo, ctx) -> bool:
    return bool(PERSISTENCE.search(p.cmdline_str))


def evaluate_process(process: ProcessInfo, blacklist) -> List[Tuple[str, str, str]]:
    """Return list of (rule_id, severity, reason) hits for one process."""
    ctx = {"blacklist": blacklist}
    hits = []
    for rule_id, severity, description, fn in _RULES:
        try:
            if fn(process, ctx):
                hits.append((rule_id, severity, description))
        except Exception:
            continue
    return hits
