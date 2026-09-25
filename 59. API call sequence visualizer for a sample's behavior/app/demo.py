"""Offline demo fixtures (architecture §8).

The workbench ships four synthetic sandbox reports so every view can be exercised
without a live sandbox and without touching a real sample.  Each fixture is built
at run time — nothing binary is stored on disk — and mirrors the shapes the
parsers must survive:

====================  =========================================================
``cape-injection``    CAPE JSON with a 3-process tree, injection + C2 behaviour
``cuckoo-ransomware`` Cuckoo JSON with mass file encryption loops
``jsonl-stealer``     normalised JSON Lines call log from a credential stealer
``cape-bson``         CAPE behaviour BSON log (encoder round-trip)
====================  =========================================================
"""
from __future__ import annotations

from app.config import APP
from app.core import bsonx
from app.core import fastjson as jsonx

CALL_SETS: dict[str, dict] = {
    "cape-injection": {
        "sample": "invoice_2026_09.doc.exe",
        "sha256": "9f2c1d4b7a5e8f0c3b6a1d9e4f7a2c5b8d1e4f7a0c3b6d9e2f5a8c1b4d7e0f3a",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 9.1,
        "signatures": [
            "injects_into_remote_process",
            "creates_hidden_file",
            "persistence_autorun",
            "network_c2_beacon",
            "antidebug_checks",
        ],
        "tree": [
            {
                "pid": 1544,
                "name": "invoice_2026_09.doc.exe",
                "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\invoice_2026_09.doc.exe",
                "command_line": "invoice_2026_09.doc.exe /quiet",
                "children": [
                    {"pid": 2212, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
                    {"pid": 3096, "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe"},
                ],
            }
        ],
        "calls": [
            (1544, "IsDebuggerPresent", "system", {"status": "FAILURE"}),
            (1544, "GetSystemInfo", "system", {}),
            (1544, "GetComputerNameW", "system", {"name": "DESKTOP-7KQ2L"}),
            (1544, "GetVolumeInformationW", "system", {"volume": "C:\\"}),
            (1544, "Process32FirstW", "process", {"process_identifier": 4, "process_name": "System"}),
            (1544, "Process32NextW", "process", {"process_identifier": 1544, "process_name": "invoice_2026_09.doc.exe"}),
            (1544, "Process32NextW", "process", {"process_identifier": 2212, "process_name": "explorer.exe"}),
            (1544, "OpenProcess", "process", {"process_identifier": 2212, "desired_access": "0x1F0FFF"}),
            (1544, "VirtualAllocEx", "memory", {"process_identifier": 2212, "size": 0x2A000, "protection": "PAGE_EXECUTE_READWRITE"}),
            (1544, "WriteProcessMemory", "memory", {"process_identifier": 2212, "size": 172032, "buffer": "4d5a90000300000004000000"}),
            (1544, "VirtualProtectEx", "memory", {"process_identifier": 2212, "new_protection": "PAGE_EXECUTE_READ"}),
            (1544, "CreateRemoteThread", "process", {"process_identifier": 2212, "start_address": "0x0000000001A40000"}),
            (1544, "SleepEx", "system", {"milliseconds": 3000}),
            (1544, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "InvoiceUpdater"}),
            (1544, "RegSetValueExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "InvoiceUpdater", "value": "C:\\Users\\analyst\\AppData\\Local\\Temp\\invoice_2026_09.doc.exe"}),
            (1544, "CreateFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost.dll", "desired_access": "GENERIC_WRITE"}),
            (1544, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost.dll", "size": 65536}),
            (1544, "CloseHandle", "file", {"handle": "0x1a4"}),
            (1544, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\rundll32.exe", "command_line": "rundll32.exe C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost.dll,Entry"}),
            (3096, "GetHostByName", "network", {"hostname": "updates.secure-delivery-cdn.com"}),
            (3096, "connect", "network", {"ip_address": "185.199.42.17", "port": 8443}),
            (3096, "send", "network", {"buffer": "POST /gate.php HTTP/1.1"}),
            (3096, "send", "network", {"buffer": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)"}),
            (3096, "send", "network", {"buffer": "Cookie: sid=Zx8f..."}),
            (3096, "send", "network", {"buffer": "body: win=1&pid=3096"}),
            (3096, "send", "network", {"buffer": "body: host=DESKTOP-7KQ2L"}),
            (3096, "recv", "network", {"size": 512}),
            (3096, "SleepEx", "system", {"milliseconds": 60000}),
            (3096, "send", "network", {"buffer": "GET /ping HTTP/1.1"}),
            (3096, "SleepEx", "system", {"milliseconds": 60000}),
            (3096, "CreateFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.lnk", "desired_access": "GENERIC_WRITE"}),
            (3096, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.lnk", "size": 2048}),
        ],
    },
    "cuckoo-ransomware": {
        "sample": "locker_2026.exe",
        "sha256": "3b7d1f5a9c2e6084d1a4f7e0b3c69d2f5a8b1e4c7d0f3a6b9c2e5d8f1a4b7c0e",
        "machine": "cuckoo-win7x64",
        "platform": "windows",
        "score": 10.0,
        "signatures": [
            "creates_service",
            "modifies_shadow_copies",
            "mass_file_encryption",
            "creates_mutex",
            "persistence_run_key",
        ],
        "tree": [
            {
                "pid": 788,
                "name": "locker_2026.exe",
                "path": "C:\\Users\\analyst\\Desktop\\locker_2026.exe",
                "command_line": "locker_2026.exe -k",
                "children": [
                    {"pid": 1216, "name": "vssadmin.exe", "path": "C:\\Windows\\System32\\vssadmin.exe"},
                    {"pid": 2044, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
                ],
            }
        ],
        "calls": [
            (788, "IsDebuggerPresent", "system", {"status": "FAILURE"}),
            (788, "CreateMutexW", "sync", {"mutex_name": "Global\\LKR-2026-LOCK", "status": "SUCCESS"}),
            (788, "FindFirstFileW", "file", {"file_name": "C:\\Users\\analyst\\Documents\\*"}),
            (788, "FindNextFileW", "file", {"file_name": "report.docx"}),
            (788, "FindNextFileW", "file", {"file_name": "budget.xlsx"}),
            (788, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\Documents\\report.docx", "size": 32768}),
            (788, "CryptGenKey", "crypto", {"algorithm": "CALG_AES_256"}),
            (788, "CryptEncrypt", "crypto", {"buffer": "7a1f0c", "size": 32768}),
            (788, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\Documents\\report.docx.locked", "size": 32768}),
            (788, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\Documents\\budget.xlsx", "size": 40960}),
            (788, "CryptEncrypt", "crypto", {"buffer": "9b2e41", "size": 40960}),
            (788, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\Documents\\budget.xlsx.locked", "size": 40960}),
            (788, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\Pictures\\scan.png", "size": 51200}),
            (788, "CryptEncrypt", "crypto", {"buffer": "1c7d55", "size": 51200}),
            (788, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\Pictures\\scan.png.locked", "size": 51200}),
            (788, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\Desktop\\notes.txt", "size": 4096}),
            (788, "CryptEncrypt", "crypto", {"buffer": "aa31de", "size": 4096}),
            (788, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\Desktop\\notes.txt.locked", "size": 4096}),
            (788, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet"}),
            (788, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c bcdedit /set {default} recoveryenabled No"}),
            (788, "CreateFileW", "file", {"file_name": "C:\\Users\\analyst\\Desktop\\README_LOCKED.txt", "desired_access": "GENERIC_WRITE"}),
            (788, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\Desktop\\README_LOCKED.txt", "size": 1024}),
            (788, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "LockerService"}),
            (788, "RegSetValueExW", "registry", {"regkey": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "LockerService", "value": "C:\\Users\\analyst\\Desktop\\locker_2026.exe -k"}),
            (788, "OpenSCManagerW", "system", {"service_name": "LockSvc"}),
            (788, "CreateServiceW", "system", {"service_name": "LockSvc", "binary_path": "C:\\Users\\analyst\\Desktop\\locker_2026.exe"}),
            (788, "StartServiceW", "system", {"service_name": "LockSvc"}),
            (788, "OpenProcess", "process", {"process_identifier": 4, "desired_access": "0x1F0FFF"}),
            (788, "ReadProcessMemory", "memory", {"process_identifier": 4, "buffer": "0100"}),
            (788, "VirtualAlloc", "memory", {"size": 131072, "protection": "PAGE_EXECUTE_READWRITE"}),
            (788, "WriteProcessMemory", "memory", {"size": 131072, "buffer": "fc4883e4f0"}),
            (788, "VirtualProtect", "memory", {"new_protection": "PAGE_EXECUTE_READ"}),
        ],
    },
    "jsonl-stealer": {
        "sample": "chromium_updater.exe",
        "sha256": "5e8a2c6b9d0f3a7b1e4c8d2f5a9b3e6c0d4f7a1b5e8c2d6f9a3b7e0c4d8f1a5b",
        "machine": "analyst-vm",
        "platform": "windows",
        "score": 7.4,
        "signatures": ["steals_browser_credentials", "reads_lsass_memory", "exfil_over_http"],
        "tree": [],
        "calls": [
            (4104, "GetUserNameW", "system", {"name": "analyst"}),
            (4104, "CreateFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "desired_access": "GENERIC_READ"}),
            (4104, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "size": 262144}),
            (4104, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\stage1.tmp", "size": 262144}),
            (4104, "CreateFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "desired_access": "GENERIC_READ"}),
            (4104, "ReadFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "size": 180224}),
            (4104, "WriteFile", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\stage2.tmp", "size": 180224}),
            (4104, "OpenProcess", "process", {"process_identifier": 692, "process_name": "lsass.exe", "desired_access": "0x1F0FFF"}),
            (4104, "ReadProcessMemory", "memory", {"process_identifier": 692, "size": 1048576}),
            (4104, "VirtualAlloc", "memory", {"size": 1048576, "protection": "PAGE_READWRITE"}),
            (4104, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\powershell.exe", "command_line": "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA" }),
            (4104, "gethostbyname", "network", {"hostname": "collect.credential-sync.net"}),
            (4104, "connect", "network", {"ip_address": "45.133.216.88", "port": 443}),
            (4104, "send", "network", {"buffer": "POST /upload HTTP/1.1"}),
            (4104, "send", "network", {"buffer": "Content-Type: multipart/form-data; boundary=----x"}),
            (4104, "send", "network", {"buffer": "stage1.tmp binary payload"}),
            (4104, "send", "network", {"buffer": "stage2.tmp binary payload"}),
            (4104, "send", "network", {"buffer": "lsass dump fragment"}),
            (4104, "recv", "network", {"size": 256}),
            (4104, "DeleteFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\stage1.tmp"}),
            (4104, "DeleteFileW", "file", {"file_name": "C:\\Users\\analyst\\AppData\\Local\\Temp\\stage2.tmp"}),
        ],
    },
    "cape-bson": {
        "sample": "loader_b7.bin",
        "sha256": "c4f0a8e2b6d19c5f3a7e0b4d8c2f6a9e1d5b7c0f4a8e2b6d9c3f7a1e5b0d4c8a",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 8.0,
        "signatures": ["unpacks_self", "hollows_process", "creates_scheduled_task"],
        "tree": [
            {
                "pid": 2748,
                "name": "loader_b7.bin",
                "children": [{"pid": 3404, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"}],
            }
        ],
        "calls": [
            (2748, "VirtualAlloc", "memory", {"size": 262144, "protection": "PAGE_EXECUTE_READWRITE"}),
            (2748, "WriteProcessMemory", "memory", {"size": 262144, "buffer": "4d5a9000"}),
            (2748, "VirtualProtect", "memory", {"new_protection": "PAGE_EXECUTE_READ"}),
            (2748, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\svchost.exe", "command_line": "svchost.exe -k netsvcs", "creation_flags": "CREATE_SUSPENDED"}),
            (2748, "NtUnmapViewOfSection", "memory", {"process_identifier": 3404, "base_address": "0x00400000"}),
            (2748, "VirtualAllocEx", "memory", {"process_identifier": 3404, "size": 409600, "protection": "PAGE_EXECUTE_READWRITE"}),
            (2748, "WriteProcessMemory", "memory", {"process_identifier": 3404, "size": 409600}),
            (2748, "SetThreadContext", "process", {"process_identifier": 3404, "context": "RIP=0x00400000"}),
            (2748, "ResumeThread", "process", {"thread_identifier": 3512}),
            (2748, "CreateProcessW", "process", {"application_name": "C:\\Windows\\System32\\schtasks.exe", "command_line": "schtasks /create /tn WindowsUpdateTask /tr C:\\Windows\\Temp\\svc.dll /sc onlogon /f"}),
            (2748, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"}),
            (2748, "RegSetValueExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "WinUpd"}),
            (3404, "gethostbyname", "network", {"hostname": "node7.relay-control.org"}),
            (3404, "connect", "network", {"ip_address": "91.219.236.14", "port": 8080}),
            (3404, "send", "network", {"buffer": "GET /api/v3/task HTTP/1.1"}),
            (3404, "send", "network", {"buffer": "X-Bot-Id: 7f3a"}),
            (3404, "send", "network", {"buffer": "SLEEP=120"}),
            (3404, "recv", "network", {"size": 128}),
        ],
    },
}

FIXTURES: list[tuple[str, str]] = [
    ("cape-injection", "CAPE JSON · injection + C2 beacon"),
    ("cuckoo-ransomware", "Cuckoo JSON · ransomware encryption loop"),
    ("jsonl-stealer", "JSON Lines · credential stealer"),
    ("cape-bson", "CAPE BSON behaviour log · hollowing"),
]

DEMO_KINDS: list[str] = [kind for kind, _label in FIXTURES]


def _call_records(kind: str, start: float = 0.4, step: float = 0.35) -> dict[int, list[dict]]:
    """Turn the fixture tuple list into Cuckoo/CAPE call dictionaries."""
    spec = CALL_SETS[kind]
    by_process: dict[int, list[dict]] = {}
    stamp = start
    for index, (pid, api, category, extra) in enumerate(spec["calls"]):
        extra = dict(extra)
        status = extra.pop("status", "SUCCESS")
        record = {
            "api": api,
            "category": category,
            "timestamp": round(stamp, 3),
            "thread_id": pid + 100,
            "status": status,
            "return_value": "0x00000000" if status == "SUCCESS" else "0xC0000005",
            "arguments": extra,
            "caller": "0x0040%04x" % (0x1000 + index * 17),
        }
        if category == "file" and api in ("FindFirstFileW", "FindNextFileW"):
            record["arguments"] = {"file_name": extra.get("file_name", "*")}
        by_process.setdefault(pid, []).append(record)
        stamp += step
    return by_process


def _process_entries(kind: str) -> list[dict]:
    spec = CALL_SETS[kind]
    entries: list[dict] = []
    names: dict[int, tuple[str, str]] = {}
    for node in _flatten_tree(spec["tree"]):
        names[node["pid"]] = (node.get("name", ""), node.get("path", ""))
    root_pid = spec["tree"][0]["pid"] if spec["tree"] else None
    for pid, calls in _call_records(kind).items():
        name, path = names.get(pid, (f"process-{pid}", ""))
        entry = {
            "process_id": pid,
            "process_name": name or f"process-{pid}",
            "first_seen": calls[0]["timestamp"] - 0.2,
            "calls": calls,
            "path": path,
        }
        if root_pid is not None and pid != root_pid:
            entry["parent_id"] = root_pid
        entries.append(entry)
    return entries


def _flatten_tree(tree: list) -> list[dict]:
    out: list[dict] = []
    for node in tree:
        out.append(node)
        out.extend(_flatten_tree(node.get("children") or []))
    return out


def _summary(kind: str) -> dict:
    spec = CALL_SETS[kind]
    files, keys, hosts, mutexes, services, commands = set(), set(), set(), set(), set(), []
    for _pid, api, category, extra in spec["calls"]:
        if category == "file" and api in ("CreateFileW", "WriteFile"):
            files.add(extra.get("file_name", ""))
        if category == "registry":
            keys.add(extra.get("regkey", ""))
        if category == "network":
            hosts.add(extra.get("hostname") or extra.get("ip_address", ""))
        if category == "sync":
            mutexes.add(extra.get("mutex_name", ""))
        if category == "system" and api.startswith(("CreateService", "StartService", "OpenSC")):
            services.add(extra.get("service_name", ""))
        if category == "process" and api == "CreateProcessW":
            commands.append(extra.get("command_line", ""))
    return {
        "files": sorted(name for name in files if name),
        "keys": sorted(name for name in keys if name),
        "mutexes": sorted(name for name in mutexes if name),
        "hosts": sorted(host for host in hosts if host),
        "services": sorted(name for name in services if name),
        "executed_commands": commands,
    }


# --------------------------------------------------------------------------- #
#  Builders
# --------------------------------------------------------------------------- #
def as_cape_json(kind: str) -> bytes:
    spec = CALL_SETS[kind]
    payload = {
        "info": {
            "machine": {"name": spec["machine"]},
            "platform": spec["platform"],
            "started": "2026-09-12 10:04:21",
            "version": "CAPE 2.4",
            "score": spec["score"],
        },
        "target": {"file": {"name": spec["sample"], "sha256": spec["sha256"], "size": 348160}},
        "analysis": {
            "started": "2026-09-12 10:04:21",
            "duration": round(len(spec["calls"]) * 0.35 + 12, 1),
            "platform": spec["platform"],
        },
        "malscore": spec["score"],
        "signatures": [{"name": name, "severity": 3} for name in spec["signatures"]],
        "behavior": {
            "processtree": spec["tree"],
            "processes": _process_entries(kind),
            "summary": _summary(kind),
        },
    }
    return jsonx.dumps(payload, indent=1).encode("utf-8")


def as_cuckoo_json(kind: str) -> bytes:
    spec = CALL_SETS[kind]
    payload = {
        "info": {
            "machine": {"name": spec["machine"]},
            "platform": spec["platform"],
            "started": "2026-09-12 11:22:05",
        },
        "target": {"file": {"name": spec["sample"], "sha256": spec["sha256"]}},
        "score": spec["score"],
        "signatures": [{"name": name} for name in spec["signatures"]],
        "behavior": {
            "processtree": spec["tree"],
            "processes": _process_entries(kind),
            "summary": _summary(kind),
        },
    }
    return jsonx.dumps(payload, indent=1).encode("utf-8")


def as_jsonl(kind: str) -> bytes:
    lines: list[str] = []
    for pid, calls in _call_records(kind).items():
        names = {node["pid"]: node.get("name", "") for node in _flatten_tree(CALL_SETS[kind]["tree"])}
        for call in calls:
            record = dict(call)
            record["process_id"] = pid
            record["process_name"] = names.get(pid, f"process-{pid}")
            lines.append(jsonx.dumps(record, indent=None))
    return ("\n".join(lines) + "\n").encode("utf-8")


def as_cape_bson(kind: str) -> bytes:
    spec = CALL_SETS[kind]
    documents = [
        {
            "info": {"machine": {"name": spec["machine"]}, "platform": spec["platform"]},
            "target": {"file": {"name": spec["sample"], "sha256": spec["sha256"]}},
            "malscore": spec["score"],
            "signatures": [{"name": name} for name in spec["signatures"]],
            "processtree": spec["tree"],
            "summary": _summary(kind),
        }
    ]
    for entry in _process_entries(kind):
        document = {
            "process_id": entry["process_id"],
            "process_name": entry["process_name"],
            "parent_id": entry.get("parent_id"),
            "calls": [
                {
                    "api": call["api"],
                    "category": call["category"],
                    "timestamp": call["timestamp"],
                    "status": call["status"],
                    "thread_id": call["thread_id"],
                    "arguments": call["arguments"],
                }
                for call in entry["calls"]
            ],
        }
        documents.append(document)
    return b"".join(bsonx.encode(document) for document in documents)


def demo_report(kind: str) -> tuple[str, bytes, str]:
    """Return ``(filename, data, format)`` for one fixture."""
    spec = CALL_SETS[kind]
    sample = spec["sample"]
    if kind == "cape-bson":
        return f"{sample}.log.bson", as_cape_bson(kind), "cape-bson"
    if kind == "jsonl-stealer":
        return f"{sample}.jsonl", as_jsonl(kind), "jsonl"
    if kind == "cuckoo-ransomware":
        return f"{sample}.json", as_cuckoo_json(kind), "cuckoo"
    return f"{sample}.json", as_cape_json(kind), "cape"


def demo_bytes(kind: str) -> bytes:
    return demo_report(kind)[1]


def fixtures() -> list[tuple[str, str]]:
    return [(kind, label) for kind, label in FIXTURES]


def fixture_rows() -> list[list]:
    rows: list[list] = []
    for kind, label in FIXTURES:
        name, data, fmt = demo_report(kind)
        rows.append([kind, label, name, fmt, len(data)])
    return rows


def run_demo(engine, kind: str, progress=None):
    """Analyse one fixture through the real pipeline."""
    if kind not in CALL_SETS:
        raise ValueError(f"unknown demo fixture '{kind}' (available: {', '.join(DEMO_KINDS)})")
    name, data, fmt = demo_report(kind)
    result = engine.analyse_bytes(data, name=name, path=f"demo://{name}", progress=progress)
    result.notes.append(
        f"Offline demo fixture '{kind}' ({fmt}); generated in memory by {APP['name']}, "
        "no live sample or network access was used."
    )
    return result


def verify_codec() -> dict:
    """Round-trip the BSON fixtures so the suite can assert the codec is intact."""
    out: dict[str, int] = {}
    for kind, _label in FIXTURES:
        name, data, fmt = demo_report(kind)
        out[f"{kind}:{fmt}"] = len(data)
    documents = bsonx.decode_all(as_cape_bson("cape-bson"))
    out["bson_documents"] = len(documents)
    return out
