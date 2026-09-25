"""API Call Sequence Visualizer - entry point.

Default is the GUI.  ``--selftest``, ``--analyze`` and ``--demo`` run the whole
pipeline headlessly and export reports, which is what the build verification and
the automated tests use.

This module is intentionally identical across the workbench suite: it only talks
to the engine through ``Engine``, ``demo.DEMO_KINDS`` and
``result.summary_rows()``.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from app.config import APP, SETTINGS, reports_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP["slug"],
        description=f"{APP['name']} v{APP['version']} - {APP['description']}",
    )
    parser.add_argument("--analyze", metavar="PATH", help="analyse an artefact headlessly and exit")
    parser.add_argument(
        "--demo",
        metavar="KIND",
        help="run a built-in demo scenario headlessly and exit (see --selftest for the list)",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run every demo scenario, export all report formats and verify the pipeline",
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="directory for exported reports (default: the reports folder in the data directory)",
    )
    parser.add_argument(
        "--formats",
        default="all",
        help="comma separated export formats: html,pdf,json,csv,md,iocs.csv or 'all'",
    )
    parser.add_argument("--quiet", action="store_true", help="do not echo the session log")
    return parser


# --------------------------------------------------------------------------- #
#  headless mode plumbing
# --------------------------------------------------------------------------- #
def _attach_parent_console() -> bool:
    """Reattach stdout/stderr to the launching console (windowed build)."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        if not ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):  # ATTACH_PARENT_PROCESS
            return False
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        return True
    except Exception:
        return False


def _ensure_streams() -> None:
    """Guarantee usable stdout/stderr: console, parent console, then a log file."""
    if sys.stdout is not None and sys.stderr is not None:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        return
    if _attach_parent_console():
        return
    try:
        logs = reports_dir().parent / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        handle = open(logs / "cli.log", "a", encoding="utf-8", errors="replace")
    except Exception:
        handle = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = handle
    if sys.stderr is None:
        sys.stderr = handle


def run_cli(args) -> int:
    _ensure_streams()
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    _ = QApplication.instance() or QApplication([])  # Qt is needed for PDF rendering

    from app import demo
    from app.bus import LogBus
    from app.core.engine import Engine
    from app.reporting import export_report

    bus = LogBus(APP["slug"])
    if not args.quiet:
        bus.record.connect(lambda rec: print(rec.format(), flush=True))
    engine = Engine(SETTINGS, bus)

    out_dir = Path(args.out) if args.out else reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = (
        ["html", "pdf", "json", "csv", "md", "iocs.csv"]
        if args.formats.strip().lower() in ("all", "")
        else [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    )

    if args.selftest:
        scenarios = [(f"demo:{kind}", kind) for kind in demo.DEMO_KINDS]
    elif args.demo:
        if args.demo not in demo.DEMO_KINDS:
            print(
                f"Unknown demo kind '{args.demo}'. Available: {', '.join(demo.DEMO_KINDS)}",
                file=sys.stderr,
            )
            return 2
        scenarios = [(f"demo:{args.demo}", args.demo)]
    elif args.analyze:
        scenarios = [("file", args.analyze)]
    else:
        return -1  # caller should start the GUI

    failures = 0
    for label, payload in scenarios:
        try:
            if label.startswith("demo:"):
                result = demo.run_demo(engine, str(payload))
            else:
                result = engine.analyze(str(payload))
        except Exception as exc:
            failures += 1
            print(f"[FAIL] {label}: {exc}", file=sys.stderr)
            continue

        report = result.report or engine.build_report(result)
        if report is None:  # pragma: no cover - defensive
            failures += 1
            print(f"[FAIL] {label}: no report was produced", file=sys.stderr)
            continue
        result.report = report

        written: list[Path] = []
        for fmt in formats:
            ext = "csv" if fmt in ("csv", "iocs.csv") else fmt
            suffix = "_iocs" if fmt == "iocs.csv" else ""
            target = out_dir / f"{report.default_stem()}{suffix}.{ext}"
            try:
                written.append(export_report(report, target, fmt))
            except Exception as exc:
                failures += 1
                print(f"[FAIL] export {fmt} for {label}: {exc}", file=sys.stderr)

        print("=" * 78)
        print(label)
        for key, value in result.summary_rows():
            print(f"  {key:<15} : {value}")
        for path in written:
            print(f"  {'wrote':<15} : {path} ({path.stat().st_size} bytes)")

    print("=" * 78)
    print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures} errors)")
    return 0 if failures == 0 else 1


# --------------------------------------------------------------------------- #
#  GUI mode
# --------------------------------------------------------------------------- #
def run_gui(argv) -> int:
    from PySide6.QtWidgets import QApplication

    from app.ui.main_window import MainWindow
    from app.ui.theme import apply_theme

    app = QApplication.instance() or QApplication(list(argv))
    app.setApplicationName(APP["name"])
    app.setApplicationVersion(APP["version"])
    app.setOrganizationName(APP["vendor"])
    apply_theme(app)

    window = MainWindow()
    window.show()
    return app.exec()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    if args.selftest or args.analyze or args.demo:
        code = run_cli(args)
        if code != -1:
            return code
    return run_gui(argv)


if __name__ == "__main__":
    raise SystemExit(main())
