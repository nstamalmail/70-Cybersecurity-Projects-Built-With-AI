"""Demo telemetry so every view is reachable without a hypervisor or real sample.

The generated sessions are **synthetic**: hand-authored event streams that
describe a plausible ransomware-style and a benign run.  They are written as
plain JSON (never as executables), and every artefact carries
``"simulation": true`` so the UI, the console and the report label them as
simulated.  Nothing here executes sample code.
"""
from __future__ import annotations

import datetime as _dt
import json
import random
from pathlib import Path

from app.config import demo_dir
from app.core.model import BehaviorEvent, ProcessNode, Session

DEMO_NOTICE = (
    "SYNTHETIC DEMO TELEMETRY - hand-authored events for interface demonstration, "
    "not the result of a real detonation."
)

DEMO_KINDS = ["detonation", "session-file", "benign"]

C2_IP = "185.220.101.44"
C2_PORT = 8443
C2_HOST = "cdn-update.demo-lab.example"
C2_PATH = "/panel/fb.png"
BEACON_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BeaconClient/3.1"
DROPPED_HASH = "9f2a4c1de8b74503fa1d6c0be2f4a9182233445566778899aabbccddeeff0011"
UPDATE_HASH = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"


def _event(ts: float, event_type: str, **kwargs) -> BehaviorEvent:
    return BehaviorEvent(ts=round(ts, 3), event_type=event_type, **kwargs)


def _ransomware_events() -> tuple[list[BehaviorEvent], list[ProcessNode]]:
    rng = random.Random(0x5EED)  # deterministic so reports are reproducible
    events: list[BehaviorEvent] = []
    sample = "C:\\Users\\Public\\svchost32.exe"
    svc = "C:\\ProgramData\\svc\\update.exe"

    events.append(
        _event(0.4, "process_create", process_id=1, process_name="svchost32.exe",
               path=sample, arguments={"command_line": sample}, status="success")
    )
    events.append(
        _event(0.9, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="IsDebuggerPresent", category="anti-analysis", return_value="0")
    )
    events.append(
        _event(1.2, "file_read", process_id=1, process_name="svchost32.exe",
               path="C:\\Windows\\System32\\drivers\\VBoxMouse.sys", operation="open",
               status="NAME NOT FOUND")
    )
    events.append(
        _event(1.3, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="GetSystemInfo", category="system", return_value="0x00000000")
    )
    events.append(
        _event(2.1, "module_load", process_id=1, process_name="svchost32.exe",
               arguments={"module": "C:\\Windows\\System32\\vboxservice.dll"})
    )
    events.append(
        _event(2.4, "file_write", process_id=1, process_name="svchost32.exe", path=sample,
               operation="write", sha256=DROPPED_HASH)
    )
    # ---- persistence
    events.append(
        _event(3.0, "registry_set", process_id=1, process_name="svchost32.exe",
               path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
               operation="set", arguments={"value_name": "WindowsUpdate", "value_data": sample})
    )
    events.append(
        _event(3.4, "registry_set", process_id=1, process_name="svchost32.exe",
               path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               operation="set", arguments={"value_name": "WinUpd", "value_data": svc})
    )
    events.append(
        _event(3.9, "service_create", process_id=1, process_name="svchost32.exe",
               arguments={"service_name": "WinDefendUpdate", "binary_path": svc},
               status="success")
    )
    encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    events.append(
        _event(4.3, "task_create", process_id=1, process_name="svchost32.exe",
               arguments={"task_name": "\\MicrosoftUpdate", "command": f"powershell -nop -w hidden -enc {encoded}"})
    )
    events.append(
        _event(4.6, "process_create", process_id=2, process_name="cmd.exe", parent_pid=1,
               arguments={"command_line": "cmd.exe /c vssadmin delete shadows /all /quiet"})
    )
    events.append(
        _event(4.7, "shell", process_id=2, process_name="cmd.exe",
               arguments={"command_line": "vssadmin delete shadows /all /quiet"})
    )
    events.append(
        _event(5.0, "process_create", process_id=3, process_name="powershell.exe", parent_pid=2,
               arguments={"command_line": f"powershell -nop -w hidden -enc {encoded}"})
    )
    # ---- dropped payload
    events.append(
        _event(5.4, "file_write", process_id=3, process_name="powershell.exe", path=svc,
               operation="write", sha256=UPDATE_HASH)
    )
    events.append(
        _event(5.6, "dropped_file", process_id=3, process_name="powershell.exe", path=svc,
               operation="create", sha256=UPDATE_HASH)
    )
    # ---- C2 discovery + beaconing
    events.append(
        _event(6.0, "dns", process_id=1, process_name="svchost32.exe",
               protocol="dns", arguments={"query": C2_HOST}, dst_ip=C2_IP)
    )
    for index in range(10):
        ts = 6.5 + index * 30.0
        events.append(
            _event(ts, "network", process_id=1, process_name="svchost32.exe",
                   dst_ip=C2_IP, dst_port=C2_PORT, protocol="tcp",
                   bytes_sent=412 + index, bytes_received=980 + index * 4, status="established")
        )
    for index in range(6):
        events.append(
            _event(9.0 + index * 30.0, "http", process_id=1, process_name="svchost32.exe",
                   path=f"https://{C2_HOST}{C2_PATH}", dst_ip=C2_IP, dst_port=443,
                   protocol="https", arguments={"method": "POST", "user-agent": BEACON_UA,
                                                "host": C2_HOST},
                   bytes_sent=1200, bytes_received=4300)
        )
    # ---- DGA-style DNS burst
    for index in range(24):
        token = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14))
        events.append(
            _event(60.0 + index * 2.4, "dns", process_id=1, process_name="svchost32.exe",
                   protocol="dns", arguments={"query": f"{token}.dyndns-demo.example"},
                   status="NXDOMAIN")
        )
    # ---- credential access
    events.append(
        _event(120.0, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="OpenProcess", category="process", arguments={"process": "lsass.exe"},
               return_value="0x0000004c")
    )
    events.append(
        _event(120.4, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="ReadProcessMemory", category="memory",
               arguments={"target": "lsass.exe", "size": "0x00100000"}, return_value="1")
    )
    # ---- injection into explorer.exe
    events.append(
        _event(140.0, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="VirtualAllocEx", category="memory",
               arguments={"process_handle": "explorer.exe", "size": "0x00040000"}, return_value="0x00200000")
    )
    events.append(
        _event(140.3, "api_call", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="WriteProcessMemory", category="memory",
               arguments={"target": "explorer.exe", "bytes": 4096}, return_value="1")
    )
    events.append(
        _event(140.6, "process_inject", process_id=1, process_name="svchost32.exe", dll="kernel32.dll",
               function="CreateRemoteThread", category="process",
               arguments={"target_pid": "explorer.exe"}, return_value="0x000000f0")
    )
    # ---- exfiltration
    events.append(
        _event(240.0, "network", process_id=1, process_name="svchost32.exe", dst_ip=C2_IP,
               dst_port=443, protocol="tcp", bytes_sent=6_800_000, bytes_received=2048,
               status="established")
    )
    # ---- mass encryption
    extensions = [".docx", ".xlsx", ".pdf", ".jpg", ".sql", ".zip", ".txt"]
    for index in range(40):
        source = f"C:\\Users\\Public\\Documents\\file_{index:03d}{rng.choice(extensions)}"
        events.append(
            _event(180.0 + index * 1.6, "file_write", process_id=1, process_name="svchost32.exe",
                   path=source + ".locked", operation="write", arguments={"encrypted": True})
        )
    for index in range(12):
        source = f"C:\\Users\\Public\\Documents\\report_{index:02d}.pdf"
        events.append(
            _event(190.0 + index * 2.0, "file_rename", process_id=1, process_name="svchost32.exe",
                   path=source + ".lockbit", operation="rename")
        )
    events.append(
        _event(255.0, "file_write", process_id=1, process_name="svchost32.exe",
               path="C:\\Users\\Public\\Documents\\HOW_TO_DECRYPT.txt", operation="write",
               data="send bitcoin to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    )
    # ---- WMI subscription
    events.append(
        _event(270.0, "api_call", process_id=1, process_name="svchost32.exe", dll="wbemdisp.dll",
               function="ExecQuery", category="system",
               arguments={"query": "SELECT * FROM __EventFilter WHERE Name='Updater'"},
               return_value="0")
    )
    # ---- self deletion
    events.append(
        _event(295.0, "file_delete", process_id=1, process_name="svchost32.exe", path=sample,
               operation="delete", status="success")
    )
    events.append(
        _event(298.0, "process_exit", process_id=3, process_name="powershell.exe")
    )
    events.append(
        _event(299.0, "process_exit", process_id=2, process_name="cmd.exe")
    )

    processes = [
        ProcessNode(pid=1, name="svchost32.exe", parent_pid=None, path=sample,
                    command_line=sample, first_seen=0.4, last_seen=295.0, user="Public"),
        ProcessNode(pid=2, name="cmd.exe", parent_pid=1,
                    path="C:\\Windows\\System32\\cmd.exe",
                    command_line="cmd.exe /c vssadmin delete shadows /all /quiet",
                    first_seen=4.6, last_seen=299.0, user="Public"),
        ProcessNode(pid=3, name="powershell.exe", parent_pid=2,
                    path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_line="powershell -nop -w hidden -enc SQBFAFgA...",
                    first_seen=5.0, last_seen=298.0, user="Public"),
        ProcessNode(pid=4, name="explorer.exe", parent_pid=1,
                    path="C:\\Windows\\explorer.exe", first_seen=139.9, last_seen=141.0,
                    user="Public", status="injected"),
        ProcessNode(pid=5, name="lsass.exe", parent_pid=None,
                    path="C:\\Windows\\System32\\lsass.exe", first_seen=0.0, last_seen=0.0,
                    user="SYSTEM", status="targeted"),
    ]
    return events, processes


def _benign_events() -> tuple[list[BehaviorEvent], list[ProcessNode]]:
    rng = random.Random(0xBEEF)
    events: list[BehaviorEvent] = []
    app = "C:\\Program Files\\Contoso\\Updater\\contoso-updater.exe"
    events.append(
        _event(0.3, "process_create", process_id=100, process_name="contoso-updater.exe",
               path=app, arguments={"command_line": f'"{app}" --check'})
    )
    for index in range(6):
        events.append(
            _event(0.8 + index * 0.4, "file_read", process_id=100,
                   process_name="contoso-updater.exe",
                   path=f"C:\\Program Files\\Contoso\\Updater\\resources\\asset_{index}.dat",
                   operation="read")
        )
    events.append(
        _event(3.0, "dns", process_id=100, process_name="contoso-updater.exe", protocol="dns",
               arguments={"query": "update.contoso.example"}, dst_ip="203.0.113.25")
    )
    events.append(
        _event(3.6, "http", process_id=100, process_name="contoso-updater.exe",
               path="https://update.contoso.example/v2/manifest.json", dst_ip="203.0.113.25",
               dst_port=443, protocol="https",
               arguments={"method": "GET",
                          "user-agent": "ContosoUpdater/2.4 (Windows 10)"},
               bytes_sent=320, bytes_received=2048)
    )
    events.append(
        _event(4.4, "file_write", process_id=100, process_name="contoso-updater.exe",
               path="C:\\ProgramData\\Contoso\\Updater\\logs\\update.log", operation="write")
    )
    events.append(
        _event(5.0, "registry_set", process_id=100, process_name="contoso-updater.exe",
               path="HKCU\\Software\\Contoso\\Updater", operation="set",
               arguments={"value_name": "LastCheck", "value_data": "2026-09-17T01:00:00Z"})
    )
    for index in range(4):
        events.append(
            _event(6.0 + index * 3.0, "api_call", process_id=100,
                   process_name="contoso-updater.exe", dll="kernel32.dll",
                   function=rng.choice(["CreateFileW", "ReadFile", "CloseHandle", "GetTickCount64"]),
                   category="file", return_value="0")
        )
    events.append(_event(20.0, "process_exit", process_id=100, process_name="contoso-updater.exe"))
    processes = [
        ProcessNode(pid=100, name="contoso-updater.exe", parent_pid=None, path=app,
                    command_line=f'"{app}" --check', first_seen=0.3, last_seen=20.0, user="Public")
    ]
    return events, processes


def synthetic_session(scenario: str = "ransomware", *, sample_name: str = "") -> Session:
    """Build a synthetic session in memory."""
    if scenario == "benign":
        events, processes = _benign_events()
        name = sample_name or "demo_benign_updater.exe.SAMPLE"
    else:
        events, processes = _ransomware_events()
        name = sample_name or "demo_svchost32.exe.SAMPLE"

    counters: dict[str, int] = {}
    for event in events:
        counters[event.event_type] = counters.get(event.event_type, 0) + 1

    return Session(
        session_id=f"das-demo-{scenario}",
        sample_name=name,
        sample_path=f"(synthetic) {name}",
        sha256=DROPPED_HASH if scenario != "benign" else "0b7a5c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        started_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=max((e.ts for e in events), default=0.0),
        source="das",
        vm_name="win10-analysis (simulated)",
        snapshot="clean-baseline",
        network_mode="simulated (INetSim/FakeNet equivalent)",
        events=events,
        processes=processes,
        counters=counters,
        simulation=True,
        warnings=[DEMO_NOTICE],
    )


def write_session_file(scenario: str = "ransomware") -> Path:
    """Write a synthetic session as JSON telemetry and return its path."""
    session = synthetic_session(scenario)
    target = demo_dir() / f"demo_{scenario}_session.json"
    payload = {
        "session": {
            "session_id": session.session_id,
            "sample_name": session.sample_name,
            "sha256": session.sha256,
            "md5": session.md5,
            "started_at": session.started_at,
            "duration": session.duration,
            "vm_name": session.vm_name,
            "snapshot": session.snapshot,
            "network_mode": session.network_mode,
            "simulation": True,
        },
        "counters": session.counters,
        "processes": [p.to_dict() for p in session.processes],
        "events": [e.to_dict() for e in session.events],
    }
    target.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    return target


def _write_sample_placeholder() -> Path:
    """Inert sample artefact used by the detonation demo (never executable)."""
    target = demo_dir() / "demo_sample_placeholder.txt.SAMPLE"
    target.write_text(
        "Inert demo artefact. This file is not executable and contains no code; it\n"
        "exists only so the detonation workflow has something to hash and submit.\n"
        "The behaviour telemetry for this scenario is synthesised by the harness.\n",
        encoding="utf-8",
    )
    return target


def run_demo(engine, kind: str, progress=None):
    """Run one of the built-in demo scenarios."""
    if kind == "detonation":
        engine._log(
            "Running the detonation workflow with the simulation harness "
            "(dry-run VM commands, synthetic telemetry)",
            "warn",
        )
        sample = _write_sample_placeholder()

        def collect(ctx):
            engine._log(
                "Simulation harness: synthesising guest telemetry "
                "(process tree, API calls, registry, file system, network)",
                "warn",
            )
            session = synthetic_session("ransomware", sample_name=sample.name)
            session.vm_name = str(ctx["adapter"].settings.get("vm_name", "win10-analysis"))
            return session

        return engine.detonate(sample, progress=progress, dry_run=True, collect=collect)

    if kind == "session-file":
        path = write_session_file("ransomware")
        engine._log(f"Wrote synthetic session telemetry to {path}", "warn")
        return engine.analyze(path, progress=progress)

    if kind == "benign":
        path = write_session_file("benign")
        engine._log(f"Wrote synthetic benign session telemetry to {path}", "info")
        return engine.analyze(path, progress=progress)

    raise ValueError(f"Unknown demo kind: {kind}")
