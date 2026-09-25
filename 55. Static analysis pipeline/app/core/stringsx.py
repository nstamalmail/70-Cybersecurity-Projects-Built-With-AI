"""String extraction and pattern classification.

Stdlib-only (no external ``strings`` binary), so the extractor behaves
identically inside a frozen executable on any platform.
"""
from __future__ import annotations

import base64
import re

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

# classification name -> compiled pattern.  Order defines primary-class priority.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("url", re.compile(r"https?://[^\s\"'<>|]{3,}", re.I)),
    ("pdb_path", re.compile(r"[A-Za-z]:\\[^\s\"']{0,200}?\.pdb", re.I)),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\b", re.I)),
    ("registry", re.compile(r"(?i)Software\\Microsoft\\Windows(?:\\CurrentVersion)?\\(?:Run|RunOnce|RunServices|Policies|Explorer|Winlogon|AppInit)")),
    ("tor_address", re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)),
    ("bitcoin", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("command", re.compile(r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|wscript|cscript|mshta|rundll32|regsvr32|reg\.exe|schtasks|wmic|vssadmin|bcdedit|netsh|bitsadmin|certutil|curl|wget)\b")),
    ("mutex", re.compile(r"\b(?:Global|Local)\\[^\s\"']{2,}")),
    ("user_agent", re.compile(r"Mozilla/\d\.\d[^\r\n]{0,140}", re.I)),
    ("credential", re.compile(r"(?i)\b(?:password|passwd|passphrase|pwd|login|username|token|api[_-]?key|secret|auth)\b\s*[:=]")),
    ("file_path", re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+")),
    ("unc_path", re.compile(r"\\\\[A-Za-z0-9._-]{1,64}\\[^\s\"']{1,160}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,12}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|info|biz|name|pro|ru|cn|su|io|xyz|top|club|online|site|live|shop|app|dev|pw|cc|tk|ml|ga|cf|gq|onion|local|lan|example)\b",
        re.I,
    )),
    ("suspicious_api", re.compile(
        r"\b(?:CreateRemoteThread(?:Ex)?|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|"
        r"NtUnmapViewOfSection|SetThreadContext|QueueUserAPC|IsDebuggerPresent|"
        r"RegSetValueEx[AW]?|CreateService[AW]?|SchRpcRegisterTask|URLDownloadToFile[AW]?|"
        r"WinExec|ShellExecute[AW]?|CryptEncrypt|BCryptEncrypt|NtCreateThreadEx)\b"
    )),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")),
    ("hash", re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")),
    ("guid", re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")),
]

CATEGORY_COLORS = {
    "url": "#4da3ff",
    "domain": "#22d3ee",
    "ipv4": "#38bdf8",
    "registry": "#a855f7",
    "file_path": "#30a46c",
    "pdb_path": "#f5a524",
    "command": "#e5484d",
    "credential": "#c4319a",
    "suspicious_api": "#f97316",
    "base64_blob": "#8b8d98",
    "user_agent": "#b08968",
    "mutex": "#818cf8",
    "tor_address": "#e5484d",
    "bitcoin": "#f5a524",
    "email": "#38bdf8",
    "hash": "#8b8d98",
    "guid": "#8b8d98",
    "unc_path": "#30a46c",
    "other": "#6b7687",
}

# keyword group -> terms used for the "suspicious keyword" summary
KEYWORD_GROUPS: dict[str, list[str]] = {
    "ransomware": [
        "encrypt", "decrypt", "bitcoin", "ransom", "vssadmin", "bcdedit",
        "shadow copy", "recoveryenabled", "wbadmin", "your files", "private key",
    ],
    "credential theft": [
        "password", "credential", "lsass", "sam", "ntds", "sekurlsa", "mimikatz",
        "keylog", "clipboard", "vault", "browser login",
    ],
    "persistence": [
        "\\run", "runonce", "runservices", "services", "schedule", "startup",
        "winlogon", "appinit", "userinit", "bootexecute", "wmi",
    ],
    "evasion": [
        "sandbox", "vmware", "virtualbox", "vbox", "qemu", "xen", "wireshark",
        "procmon", "process monitor", "x64dbg", "ollydbg", "isdebuggerpresent",
        "sleep", "mouse move", "idle time",
    ],
    "c2": [
        "beacon", "c2", "command and control", "/gate.php", "/panel/", "implant",
        "botid", "watermark", "checkin", "task.php", "submit.php",
    ],
    "lateral movement": [
        "psexec", "wmic", "net use", "smbexec", "winrm", "admin$", "c$",
    ],
}


def extract_strings(
    data: bytes,
    min_length: int = 4,
    include_wide: bool = True,
    limit: int = 250_000,
) -> list[dict]:
    """Extract ASCII and (optionally) UTF-16LE strings from a byte buffer."""
    out: list[dict] = []
    if not data:
        return out
    for match in ASCII_RE.finditer(data):
        raw = match.group()
        if len(raw) < min_length:
            continue
        out.append(
            {
                "offset": match.start(),
                "type": "ascii",
                "value": raw.decode("latin-1", "replace"),
                "length": len(raw),
            }
        )
        if len(out) >= limit:
            return out
    if include_wide:
        for match in WIDE_RE.finditer(data):
            raw = match.group()
            if len(raw) // 2 < min_length:
                continue
            try:
                text = raw.decode("utf-16-le", "replace").rstrip("\x00")
            except Exception:
                continue
            if len(text) < min_length:
                continue
            out.append(
                {
                    "offset": match.start(),
                    "type": "unicode",
                    "value": text,
                    "length": len(text),
                }
            )
            if len(out) >= limit:
                return out
    out.sort(key=lambda item: item["offset"])
    return out


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def _valid_base64(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception:
        return False
    if len(decoded) < 16:
        return False
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return printable / max(1, len(decoded)) > 0.75


def classify(value: str) -> list[str]:
    """Return every classification that applies to ``value`` (primary first)."""
    labels: list[str] = []
    for name, pattern in PATTERNS:
        match = pattern.search(value)
        if not match:
            continue
        if name == "ipv4" and not _valid_ipv4(match.group()):
            continue
        if name == "base64_blob":
            if len(value) < 32 or not _valid_base64(value):
                continue
        if name == "credential" and not pattern.search(value):
            continue
        if name == "domain":
            candidate = match.group().lower()
            if any(candidate.endswith(ext) for ext in (".exe", ".dll", ".sys", ".dat", ".tmp")):
                continue
        labels.append(name)
    return labels or ["other"]


def extract_and_classify(
    data: bytes,
    min_length: int = 4,
    include_wide: bool = True,
    progress=None,
    limit: int = 250_000,
) -> tuple[list[dict], dict]:
    """Extract + classify strings and return ``(rows, statistics)``."""
    strings = extract_strings(data, min_length, include_wide, limit)
    rows: list[dict] = []
    counts: dict[str, int] = {}
    if progress:
        progress("Classifying strings", 0, len(strings))
    for idx, item in enumerate(strings):
        labels = classify(item["value"])
        primary = labels[0]
        counts[primary] = counts.get(primary, 0) + 1
        rows.append(
            {
                "offset": item["offset"],
                "offset_hex": f"0x{item['offset']:08x}",
                "type": item["type"],
                "value": item["value"],
                "length": item["length"],
                "classification": primary,
                "labels": labels,
            }
        )
        if progress and idx % 2000 == 0:
            progress("Classifying strings", idx, len(strings))
    stats = {
        "total": len(rows),
        "ascii": sum(1 for r in rows if r["type"] == "ascii"),
        "unicode": sum(1 for r in rows if r["type"] == "unicode"),
        "by_classification": counts,
        "interesting": sum(
            counts.get(k, 0)
            for k in (
                "url", "domain", "ipv4", "registry", "command", "credential",
                "suspicious_api", "mutex", "tor_address", "bitcoin", "user_agent",
                "pdb_path",
            )
        ),
    }
    return rows, stats


def keyword_hits(rows: list[dict]) -> dict[str, list[str]]:
    """Group strings by keyword theme (ransomware, credential theft, ...)."""
    found: dict[str, list[str]] = {}
    for row in rows:
        low = row["value"].lower()
        for group, terms in KEYWORD_GROUPS.items():
            for term in terms:
                if term in low:
                    bucket = found.setdefault(group, [])
                    if len(bucket) < 40 and row["value"] not in bucket:
                        bucket.append(row["value"][:180])
                    break
    return found


def interesting_rows(rows: list[dict]) -> list[dict]:
    """Rows whose primary classification is actionable for triage."""
    wanted = {
        "url", "domain", "ipv4", "registry", "command", "credential",
        "suspicious_api", "mutex", "tor_address", "bitcoin", "user_agent",
        "pdb_path", "unc_path",
    }
    return [r for r in rows if r["classification"] in wanted]
