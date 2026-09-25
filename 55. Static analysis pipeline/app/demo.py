"""Demo fixtures so every view is reachable without real malware.

Safety note (important):
the synthetic "packed" sample is a hand-built PE image with packer-like traits.
It contains **no executable code** - it is inert header data plus strings - but
endpoint protection legitimately quarantines such files on write.  The packed
sample is therefore built **in memory only** and analysed through the buffer
path: nothing suspicious is ever written to disk.  Only the benign variant and
an inert text sample are written to the demo folder.

Everything produced here is labelled SYNTHETIC in the UI, the console and the
report so it can never be confused with a real sample verdict.
"""
from __future__ import annotations

from pathlib import Path

from app.config import demo_dir
from app.core.engine import AnalysisEngine, AnalysisResult
from app.core.pebuilder import build_pe

#: Demo scenarios offered by the UI and exercised by ``--selftest``.
DEMO_KINDS = ["packed", "benign", "script"]

DEMO_NOTICE = (
    "SYNTHETIC DEMO DATA - hand-built inert bytes for interface demonstration, "
    "not a real malware sample and not threat intelligence."
)

TEXT_SAMPLE = """#!/bin/sh
# Inert demo script (no executable payload) used to exercise the strings-only path.
REMOTE="http://c2.demo-lab.example/gate.php"
SECOND="https://cdn-update.demo-lab.example/panel/fb.png"
BEACON_IP="185.220.101.44:8443"
AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) BeaconClient/3.1"
DROP="C:/Users/Public/svchost32.exe"
KEY="Software/Microsoft/Windows/CurrentVersion/Run"
PASSWORD="admin123"
blob="aGVsbG8gdGhpcyBpcyBhIGRlbW8gcGF5bG9hZCBibG9iIGZvciB0cmlhZ2U="
# The commands below are quoted strings only; nothing here is executed.
COMMANDS="cmd.exe /c vssadmin delete shadows /all /quiet; bcdedit /set {default} recoveryenabled No"
"""


def ensure_benign_file() -> Path:
    """Write the benign demo executable (safe: no packer traits) and return it."""
    target = demo_dir() / "demo_benign_update.exe.SAMPLE"
    target.write_bytes(build_pe("clean"))
    return target


def ensure_text_file() -> Path:
    """Write the inert text sample used for the strings-only path."""
    target = demo_dir() / "demo_script.sh.SAMPLE"
    target.write_text(TEXT_SAMPLE, encoding="utf-8")
    return target


def run_demo(engine: AnalysisEngine, kind: str, progress=None) -> AnalysisResult:
    """Run one of the built-in demo scenarios.

    ``kind`` is one of ``packed`` (in-memory synthetic), ``benign`` (file on
    disk) or ``script`` (text file on disk).
    """
    if kind == "packed":
        engine._log(
            "Building synthetic packed sample in memory (never written to disk)",
            "info",
        )
        result = engine.analyze_bytes(
            build_pe("packed"),
            file_name="demo_synthetic_packed.exe.SAMPLE (in-memory)",
            progress=progress,
        )
        result.warnings.append(DEMO_NOTICE)
        result.report.title = "Static Analysis Report \u2014 synthetic packed demo"
        return result

    if kind == "benign":
        path = ensure_benign_file()
        result = engine.analyze(path, progress=progress)
        result.warnings.append(DEMO_NOTICE)
        return result

    if kind == "script":
        path = ensure_text_file()
        result = engine.analyze(path, progress=progress)
        result.warnings.append(DEMO_NOTICE)
        return result

    raise ValueError(f"Unknown demo kind: {kind}")
