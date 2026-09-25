"""Offline demo fixtures for the Malware Persistence Technique Cataloger."""
from __future__ import annotations

from app.config import APP
from app.core import fastjson as jsonx

CALL_SETS: dict[str, dict] = {
    "emotet-runkey": {
        "sample": "invoice_emotet.exe",
        "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "machine": "cuckoo-win10x64",
        "platform": "windows",
        "score": 8.5,
        "signatures": ["creates_persistence_run_key", "drops_executable", "network_c2"],
        "tree": [{"pid": 1200, "name": "invoice_emotet.exe", "path": "C:\\\\Users\\\\analyst\\\\Desktop\\\\invoice_emotet.exe",
                  "children": [{"pid": 2800, "name": "cmd.exe"}]}],
        "calls": [
            (1200, "IsDebuggerPresent", "system", {}),
            (1200, "GetUserNameW", "system", {"name": "analyst"}),
            (1200, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "InvoiceLoader"}),
            (1200, "RegSetValueExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "InvoiceLoader", "value": "C:\\\\Users\\\\analyst\\\\AppData\\\\Roaming\\\\invoice.exe"}),
            (1200, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\AppData\\\\Roaming\\\\invoice.exe", "desired_access": "GENERIC_WRITE"}),
            (1200, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\analyst\\\\AppData\\\\Roaming\\\\invoice.exe", "size": 245760}),
            (1200, "CloseHandle", "file", {}),
            (1200, "CreateProcessW", "process", {"application_name": "C:\\\\Windows\\\\System32\\\\cmd.exe", "command_line": "cmd.exe /c start C:\\\\Users\\\\analyst\\\\AppData\\\\Roaming\\\\invoice.exe"}),
            (2800, "gethostbyname", "network", {"hostname": "mail.server-update.net"}),
            (2800, "connect", "network", {"ip_address": "185.220.101.45", "port": 443}),
            (2800, "send", "network", {"buffer": "POST /gate.php"}),
            (2800, "recv", "network", {"size": 1024}),
        ],
    },
    "trickbot-service": {
        "sample": "loader_trickbot.dll",
        "sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 9.2,
        "signatures": ["creates_service", "persistence_autorun", "credential_access"],
        "tree": [{"pid": 3400, "name": "loader_trickbot.dll", "path": "C:\\\\Windows\\\\Temp\\\\loader.dll",
                  "children": [{"pid": 4100, "name": "svchost.exe"}]}],
        "calls": [
            (3400, "OpenSCManagerW", "system", {"machine_name": "", "database_name": "ServicesActive"}),
            (3400, "CreateServiceW", "system", {"service_name": "WindowsUpdateSvc", "binary_path": "C:\\\\Windows\\\\Temp\\\\loader.dll", "display_name": "Windows Update Service"}),
            (3400, "StartServiceW", "system", {"service_name": "WindowsUpdateSvc"}),
            (3400, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "WinUpdate"}),
            (3400, "RegSetValueExW", "registry", {"regkey": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "WinUpdate", "value": "C:\\\\Windows\\\\Temp\\\\loader.dll"}),
            (3400, "CreateFileW", "file", {"file_name": "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts", "desired_access": "GENERIC_READ"}),
            (4100, "OpenProcess", "process", {"process_identifier": 692, "process_name": "lsass.exe"}),
            (4100, "ReadProcessMemory", "memory", {"process_identifier": 692, "size": 2097152}),
            (4100, "gethostbyname", "network", {"hostname": "exfil.trickbot-c2.com"}),
            (4100, "connect", "network", {"ip_address": "91.215.85.142", "port": 449}),
            (4100, "send", "network", {"buffer": "POST /upload"}),
        ],
    },
    "cobaltstrike-task": {
        "sample": "beacon_cobalt.exe",
        "sha256": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 9.8,
        "signatures": ["process_injection", "scheduled_task", "c2_beacon"],
        "tree": [{"pid": 5500, "name": "beacon_cobalt.exe", "path": "C:\\\\Users\\\\analyst\\\\AppData\\\\Local\\\\Temp\\\\beacon.exe",
                  "children": [{"pid": 6200, "name": "explorer.exe"}]}],
        "calls": [
            (5500, "IsDebuggerPresent", "system", {}),
            (5500, "OpenProcess", "process", {"process_identifier": 6200, "desired_access": "0x1F0FFF"}),
            (5500, "VirtualAllocEx", "memory", {"process_identifier": 6200, "size": 65536, "protection": "PAGE_EXECUTE_READWRITE"}),
            (5500, "WriteProcessMemory", "memory", {"process_identifier": 6200, "size": 65536}),
            (5500, "CreateRemoteThread", "process", {"process_identifier": 6200}),
            (5500, "CreateProcessW", "process", {"application_name": "C:\\\\Windows\\\\System32\\\\schtasks.exe", "command_line": "schtasks /create /tn \"SystemHealthCheck\" /tr \"C:\\\\Users\\\\analyst\\\\AppData\\\\Local\\\\Temp\\\\beacon.exe\" /sc onlogon /f"}),
            (5500, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"}),
            (5500, "RegSetValueExW", "registry", {"regkey": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "SystemHealth", "value": "C:\\\\Users\\\\analyst\\\\AppData\\\\Local\\\\Temp\\\\beacon.exe"}),
            (5500, "CreateFileW", "file", {"file_name": "C:\\\\Users\\\\Public\\\\Documents\\\\stager.dll", "desired_access": "GENERIC_WRITE"}),
            (5500, "WriteFile", "file", {"file_name": "C:\\\\Users\\\\Public\\\\Documents\\\\stager.dll", "size": 131072}),
            (6200, "gethostbyname", "network", {"hostname": "collab.office365-update.com"}),
            (6200, "connect", "network", {"ip_address": "104.194.160.88", "port": 8443}),
            (6200, "send", "network", {"buffer": "GET /submit.php?id=048"}),
            (6200, "send", "network", {"buffer": "User-Agent: Mozilla/5.0"}),
        ],
    },
    "metasploit-migrate": {
        "sample": "shellcode_msf.bin",
        "sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        "machine": "cuckoo-win7x64",
        "platform": "windows",
        "score": 7.8,
        "signatures": ["process_injection", "shellcode_execution"],
        "tree": [{"pid": 7000, "name": "shellcode_msf.bin", "path": "C:\\\\Users\\\\analyst\\\\Desktop\\\\shellcode.bin",
                  "children": []}],
        "calls": [
            (7000, "VirtualAlloc", "memory", {"size": 131072, "protection": "PAGE_EXECUTE_READWRITE"}),
            (7000, "RtlMoveMemory", "memory", {"size": 131072}),
            (7000, "VirtualProtect", "memory", {"new_protection": "PAGE_EXECUTE_READ"}),
            (7000, "CreateThread", "process", {"start_address": "0x0000000000070000"}),
            (7000, "OpenProcess", "process", {"process_identifier": 4, "process_name": "System"}),
            (7000, "VirtualAllocEx", "memory", {"process_identifier": 4, "size": 65536}),
            (7000, "WriteProcessMemory", "memory", {"process_identifier": 4, "size": 65536}),
            (7000, "CreateRemoteThread", "process", {"process_identifier": 4}),
        ],
    },
    "runcabinet-comhijack": {
        "sample": "cabinet_loader.exe",
        "sha256": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "machine": "cape-vm-win10x64",
        "platform": "windows",
        "score": 8.0,
        "signatures": ["com_hijack", "dll_side_loading"],
        "tree": [{"pid": 8500, "name": "cabinet_loader.exe", "path": "C:\\\\Windows\\\\cabinet.dll",
                  "children": []}],
        "calls": [
            (8500, "RegCreateKeyExW", "registry", {"regkey": r"HKEY_CLASSES_ROOT\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32"}),
            (8500, "RegSetValueExW", "registry", {"regkey": r"HKEY_CLASSES_ROOT\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32", "value_name": "", "value": "C:\\\\Windows\\\\cabinet.dll"}),
            (8500, "CreateFileW", "file", {"file_name": "C:\\\\Windows\\\\cabinet.dll", "desired_access": "GENERIC_WRITE"}),
            (8500, "WriteFile", "file", {"file_name": "C:\\\\Windows\\\\cabinet.dll", "size": 81920}),
            (8500, "CoCreateInstance", "system", {"clsid": "{00000000-0000-0000-0000-000000000000}"}),
        ],
    },
}

FIXTURES: list[tuple[str, str]] = [
    ("emotet-runkey", "Emotet-style Run key persistence"),
    ("trickbot-service", "TrickBot-style service + Run key"),
    ("cobaltstrike-task", "Cobalt Strike scheduled task + injection"),
    ("metasploit-migrate", "Metasploit process migration (shellcode)"),
    ("runcabinet-comhijack", "COM object hijacking + DLL sideloading"),
]

DEMO_KINDS: list[str] = [kind for kind, _label in FIXTURES]


def _call_records(kind: str) -> dict[int, list[dict]]:
    spec = CALL_SETS[kind]
    by_process: dict[int, list[dict]] = {}
    stamp = 0.4
    for index, (pid, api, category, extra) in enumerate(spec["calls"]):
        extra = dict(extra)
        status = extra.pop("status", "SUCCESS")
        record = {
            "api": api, "category": category, "timestamp": round(stamp, 3),
            "status": status, "return_value": "0x00000000" if status == "SUCCESS" else "0xC0000005",
            "arguments": extra,
        }
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
    files, keys, hosts, services = set(), set(), set(), set()
    for _pid, api, category, extra in spec["calls"]:
        if category == "file" and api in ("CreateFileW", "WriteFile"):
            files.add(extra.get("file_name", ""))
        if category == "registry":
            keys.add(extra.get("regkey", ""))
        if category == "network":
            hosts.add(extra.get("hostname") or extra.get("ip_address", ""))
        if category == "system" and "service" in api.lower():
            services.add(extra.get("service_name", ""))
    return {"files": sorted(n for n in files if n), "keys": sorted(n for n in keys if n),
            "hosts": sorted(h for h in hosts if h), "services": sorted(n for n in services if n)}


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
    if kind in ("trickbot-service", "cobaltstrike-task", "runcabinet-comhijack"):
        return f"{sample}.json", as_cape_json(kind), "cape"
    return f"{sample}.json", as_cuckoo_json(kind), "cuckoo"


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
