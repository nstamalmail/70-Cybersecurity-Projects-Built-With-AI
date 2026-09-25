# MMPS - Multi-Mode Port Scanner: State

## Status: COMPLETE (built, smoke-tested, sample-importable)

## What this is
GUI port scanner per `architecture.md`: TCP-connect and SYN-scan modes, service/version
detection via banner grabbing, CVE-hint lookup, risk scoring, next-step recommendations,
and reports in TXT/JSON/CSV/HTML/PDF. PySide6 dark-themed GUI (PyInstaller-ready).

## Components
- `src/mmps/engine.py`     - scan engine: TCP connect, raw SYN (best-effort, falls back
  to connect when no admin rights), banner grabbing, service map, risk model.
- `src/mmps/reporting.py`  - single report dict -> TXT/JSON/CSV/HTML/PDF exporters.
- `src/mmps/theme.py`      - shared dark QSS theme.
- `src/mmps/main.py`       - PySide6 GUI: scan controls, results table, detail pane,
  risk summary, File > Import Scan (JSON), File > Export Report.
- `sample_data/`           - `scan_targets.txt` (bulk target list),
  `scan_legacy_server.json`, `scan_vulnerable_web.json` (importable results).
- `tests/smoke_gui.py`     - engine + report + import + GUI smoke test (offscreen Qt).

## How to run
```
cd "04. Port scanner (...)"
python src/mmps/main.py          # GUI
python tests/smoke_gui.py        # smoke test
```

## Verified
- TCP connect scan against local listener; SYN mode degrades gracefully without admin.
- Banner grab populates service/version; CVE hints attach to known banners.
- All 5 report formats written and non-trivial (smoke test asserts sizes/PDF magic).
- Import of both sample JSONs renders full results and exports reports.
- GUI boots offscreen, table rows populate, export dialog path exercised.

## Notes
- SYN scan uses raw sockets when available; without admin it logs a warning and uses
  TCP connect so the app never crashes for the user.
- Import schema == export schema (see `sample_data/*.json`), so round-trips are lossless.
