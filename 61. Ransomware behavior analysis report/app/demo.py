"""Offline demo fixtures for the Ransomware Behavior Analysis Report."""
from __future__ import annotations

from app.config import APP
from app.core import fastjson as jsonx

CALL_SETS: dict[str, dict] = {
    "lockbit-rapid": {
        "sample": "locker_lockbit.exe",
        "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "machine": "cuckoo-win10x64",
        "platform": "windows",
        "score": 10.0,
        "signatures": ["mass_file_encryption", "modifies_shadow_copies", "drops_ransom_note"],
        "tree": [{"pid": 1100, "name": "locker_lockbit.exe", "path": "C:\\\\Users\\\\analyst\\\\Desktop\\\\locker_lockbit.exe",
                  "children": [{"pid": 2200, "name": "vssadmin.exe"}]}],
        "calls": [
            (1100, "CreateMutexW", "sync", {"mutex_name": "Global\\\\LockBit-2026"}),
            (1100, "FindFirstFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\*"}),
            (1100, "FindNextFileW", "file", {"file_name": "report.docx"}),
            (1100, "FindNextFileW", "file", {"file_name": "budget.xlsx"}),
            (1100, "FindNextFileW", "file", {"file_name": "photo.jpg"}),
            (1100, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\report.docx", "desired_access": "GENERIC_READ"}),
            (1100, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\report.docx", "size": 32768}),
            (1100, "CryptGenKey", "crypto", {"algorithm": "CALG_AES_256"}),
            (1100, "CryptEncrypt", "crypto", {"buffer": "7a1f0c", "size": 32768}),
            (1100, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\report.docx.lockbit", "desired_access": "GENERIC_WRITE"}),
            (1100, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\report.docx.lockbit", "size": 32768}),
            (1100, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\budget.xlsx", "desired_access": "GENERIC_READ"}),
            (1100, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\budget.xlsx", "size": 40960}),
            (1100, "CryptEncrypt", "crypto", {"buffer": "9b2e41", "size": 40960}),
            (1100, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\budget.xlsx.lockbit", "size": 40960}),
            (1100, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Pictures\\\\photo.jpg", "desired_access": "GENERIC_READ"}),
            (1100, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Pictures\\\\photo.jpg", "size": 51200}),
            (1100, "CryptEncrypt", "crypto", {"buffer": "1c7d55", "size": 51200}),
            (1100, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Pictures\\\\photo.jpg.lockbit", "size": 51200}),
            (1100, "CreateProcessW", "process", {"application_name": "C:\\\\Windows\\\\System32\\\\vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet"}),
            (1100, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\README_LOCKED.txt", "desired_access": "GENERIC_WRITE"}),
            (1100, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\README_LOCKED.txt", "size": 2048}),
            (1100, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\report.docx"}),
            (1100, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\budget.xlsx"}),
        ],
    },
    "blackcat-staged": {
        "sample": "blackcat_loader.exe",
        "sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 9.5,
        "signatures": ["reconnaissance", "file_encryption", "ransom_note"],
        "tree": [{"pid": 3300, "name": "blackcat_loader.exe", "path": "C:\\\\Windows\\\\Temp\\\\loader.exe",
                  "children": []}],
        "calls": [
            (3300, "GetSystemInfo", "system", {}),
            (3300, "GetComputerNameW", "system", {"name": "WORKSTATION-01"}),
            (3300, "Process32FirstW", "process", {"process_identifier": 4, "process_name": "System"}),
            (3300, "Process32NextW", "process", {"process_identifier": 3300, "process_name": "blackcat_loader.exe"}),
            (3300, "Process32NextW", "process", {"process_identifier": 892, "process_name": "svchost.exe"}),
            (3300, "GetVolumeInformationW", "system", {"volume": "C:\\\\"}),
            (3300, "FindFirstFileW", "file", {"file_name": "C:\\\\Users\\\\*"}),
            (3300, "FindFirstFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\*"}),
            (3300, "FindNextFileW", "file", {"file_name": "data.csv"}),
            (3300, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\data.csv", "desired_access": "GENERIC_READ"}),
            (3300, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\data.csv", "size": 65536}),
            (3300, "CryptGenKey", "crypto", {"algorithm": "CALG_AES_256"}),
            (3300, "CryptEncrypt", "crypto", {"buffer": "aa11bb", "size": 65536}),
            (3300, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\data.csv.alphv", "size": 65536}),
            (3300, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\RECOVER-FILES.txt", "desired_access": "GENERIC_WRITE"}),
            (3300, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\RECOVER-FILES.txt", "size": 4096}),
            (3300, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\data.csv"}),
        ],
    },
    "conti-encrypt": {
        "sample": "conti_encryptor.exe",
        "sha256": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "machine": "cuckoo-win7x64",
        "platform": "windows",
        "score": 9.8,
        "signatures": ["encryption_loop", "shadow_copy_deletion", "ransom_note_drop"],
        "tree": [{"pid": 4400, "name": "conti_encryptor.exe", "path": "C:\\\\Users\\\\analyst\\\\Desktop\\\\conti.exe",
                  "children": [{"pid": 5100, "name": "cmd.exe"}]}],
        "calls": [
            (4400, "FindFirstFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\*"}),
            (4400, "FindNextFileW", "file", {"file_name": "notes.txt"}),
            (4400, "FindNextFileW", "file", {"file_name": "presentation.pptx"}),
            (4400, "FindNextFileW", "file", {"file_name": "database.db"}),
            (4400, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\notes.txt", "desired_access": "GENERIC_READ"}),
            (4400, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\notes.txt", "size": 4096}),
            (4400, "CryptGenKey", "crypto", {"algorithm": "CALG_AES_256"}),
            (4400, "CryptEncrypt", "crypto", {"buffer": "cc44dd", "size": 4096}),
            (4400, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\notes.txt.encrypted", "size": 4096}),
            (4400, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\presentation.pptx", "desired_access": "GENERIC_READ"}),
            (4400, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\presentation.pptx", "size": 131072}),
            (4400, "CryptEncrypt", "crypto", {"buffer": "ee55ff", "size": 131072}),
            (4400, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\presentation.pptx.encrypted", "size": 131072}),
            (4400, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\database.db", "desired_access": "GENERIC_READ"}),
            (4400, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\database.db", "size": 262144}),
            (4400, "CryptEncrypt", "crypto", {"buffer": "1122aa", "size": 262144}),
            (4400, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\database.db.encrypted", "size": 262144}),
            (4400, "CreateProcessW", "process", {"application_name": "C:\\\\Windows\\\\System32\\\\cmd.exe", "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet"}),
            (4400, "CreateProcessW", "process", {"application_name": "C:\\\\Windows\\\\System32\\\\cmd.exe", "command_line": "cmd.exe /c bcdedit /set {default} recoveryenabled No"}),
            (4400, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\HOW_TO_DECRYPT.txt", "desired_access": "GENERIC_WRITE"}),
            (4400, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\Desktop\\\\HOW_TO_DECRYPT.txt", "size": 3072}),
            (4400, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\notes.txt"}),
            (4400, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\presentation.pptx"}),
            (4400, "DeleteFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\Documents\\\\database.db"}),
        ],
    },
    "generic-bulk": {
        "sample": "bulk_encryptor.exe",
        "sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        "machine": "cuckoo-win10x64",
        "platform": "windows",
        "score": 8.0,
        "signatures": ["mass_file_modification"],
        "tree": [{"pid": 6600, "name": "bulk_encryptor.exe", "path": "C:\\\\Temp\\\\encryptor.exe", "children": []}],
        "calls": [
            (6600, "FindFirstFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\*"}),
            (6600, "FindNextFileW", "file", {"file_name": "file1.txt"}),
            (6600, "FindNextFileW", "file", {"file_name": "file2.txt"}),
            (6600, "FindNextFileW", "file", {"file_name": "file3.txt"}),
            (6600, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file1.txt", "desired_access": "GENERIC_READ"}),
            (6600, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file1.txt", "size": 1024}),
            (6600, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file1.txt.encrypted", "size": 1024}),
            (6600, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file2.txt", "desired_access": "GENERIC_READ"}),
            (6600, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file2.txt", "size": 2048}),
            (6600, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file2.txt.encrypted", "size": 2048}),
            (6600, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file3.txt", "desired_access": "GENERIC_READ"}),
            (6600, "ReadFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file3.txt", "size": 4096}),
            (6600, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\file3.txt.encrypted", "size": 4096}),
        ],
    },
}

FIXTURES: list[tuple[str, str]] = [
    ("lockbit-rapid", "LockBit-style rapid encryption + shadow deletion"),
    ("blackcat-staged", "BlackCat/ALPHV-style staged reconnaissance + encryption"),
    ("conti-encrypt", "Conti-style bulk encryption + ransom note"),
    ("generic-bulk", "Generic bulk file modification"),
]

DEMO_KINDS: list[str] = [kind for kind, _label in FIXTURES]


def _call_records(kind: str) -> dict[int, list[dict]]:
    spec = CALL_SETS[kind]
    by_process: dict[int, list[dict]] = {}
    stamp = 0.4
    for index, (pid, api, category, extra) in enumerate(spec["calls"]):
        extra = dict(extra)
        status = extra.pop("status", "SUCCESS")
        record = {"api": api, "category": category, "timestamp": round(stamp, 3),
                  "status": status, "return_value": "0x00000000" if status == "SUCCESS" else "0xC0000005",
                  "arguments": extra}
        by_process.setdefault(pid, []).append(record)
        stamp += 0.35
    return by_process


def _process_entries(kind: str) -> list[dict]:
    spec = CALL_SETS[kind]
    names = {}
    for node in spec["tree"]:
        names[node["pid"]] = (node.get("name", ""), node.get("path", ""))
        for child in node.get("children", []):
            names[child["pid"]] = (child.get("name", ""), child.get("path", ""))
    root_pid = spec["tree"][0]["pid"] if spec["tree"] else None
    entries = []
    for pid, calls in _call_records(kind).items():
        name, path = names.get(pid, (f"process-{pid}", ""))
        entry = {"process_id": pid, "process_name": name or f"process-{pid}",
                 "first_seen": calls[0]["timestamp"] - 0.2, "calls": calls, "path": path}
        if root_pid is not None and pid != root_pid:
            entry["parent_id"] = root_pid
        entries.append(entry)
    return entries


def _summary(kind: str) -> dict:
    spec = CALL_SETS[kind]
    files, keys, hosts = set(), set(), set()
    for _pid, api, category, extra in spec["calls"]:
        if category == "file" and api in ("CreateFileW", "WriteFile"):
            files.add(extra.get("file_name", ""))
        if category == "registry":
            keys.add(extra.get("regkey", ""))
        if category == "network":
            hosts.add(extra.get("hostname") or extra.get("ip_address", ""))
    return {"files": sorted(n for n in files if n), "keys": sorted(n for n in keys if n),
            "hosts": sorted(h for h in hosts if h)}


def as_cape_json(kind: str) -> bytes:
    spec = CALL_SETS[kind]
    payload = {
        "info": {"machine": {"name": spec["machine"]}, "platform": spec["platform"],
                 "started": "2026-09-12 10:04:21"},
        "target": {"file": {"name": spec["sample"], "sha256": spec["sha256"]}},
        "analysis": {"started": "2026-09-12 10:04:21",
                     "duration": round(len(spec["calls"]) * 0.35 + 12, 1)},
        "malscore": spec["score"],
        "signatures": [{"name": name, "severity": 3} for name in spec["signatures"]],
        "behavior": {"processtree": spec["tree"], "processes": _process_entries(kind),
                     "summary": _summary(kind)},
    }
    return jsonx.dumps(payload, indent=1).encode("utf-8")


def as_cuckoo_json(kind: str) -> bytes:
    spec = CALL_SETS[kind]
    payload = {
        "info": {"machine": {"name": spec["machine"]}, "platform": spec["platform"],
                 "started": "2026-09-12 11:22:05"},
        "target": {"file": {"name": spec["sample"], "sha256": spec["sha256"]}},
        "score": spec["score"],
        "signatures": [{"name": name} for name in spec["signatures"]],
        "behavior": {"processtree": spec["tree"], "processes": _process_entries(kind),
                     "summary": _summary(kind)},
    }
    return jsonx.dumps(payload, indent=1).encode("utf-8")


def demo_report(kind: str) -> tuple[str, bytes, str]:
    spec = CALL_SETS[kind]
    sample = spec["sample"]
    if kind in ("lockbit-rapid", "conti-encrypt"):
        return f"{sample}.json", as_cuckoo_json(kind), "cuckoo"
    return f"{sample}.json", as_cape_json(kind), "cape"


def demo_bytes(kind: str) -> bytes:
    return demo_report(kind)[1]


def fixtures() -> list[tuple[str, str]]:
    return [(kind, label) for kind, label in FIXTURES]


def fixture_rows() -> list[list]:
    rows = []
    for kind, label in FIXTURES:
        name, data, fmt = demo_report(kind)
        rows.append([kind, label, name, fmt, len(data)])
    return rows


def run_demo(engine, kind: str, progress=None):
    if kind not in CALL_SETS:
        raise ValueError(f"unknown demo fixture '{kind}'")
    name, data, fmt = demo_report(kind)
    result = engine.analyse_bytes(data, name=name, path=f"demo://{name}", progress=progress)
    result.notes.append(f"Offline demo fixture '{kind}' ({fmt}); generated in memory, no live sample used.")
    return result
