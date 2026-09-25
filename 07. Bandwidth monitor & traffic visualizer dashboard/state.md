# BMTVD - Bandwidth Monitor & Traffic Visualizer: State

## Status: COMPLETE (psutil live capture + charts + import + reports verified)

## What this is
Live bandwidth dashboard per `architecture.md`: psutil-based per-interface counters,
upload/download rate snapshots, connection counts, live line charts (QtCharts), a
process table, a history chart for imported data, and reports in TXT/JSON/CSV/HTML/PDF.

## Components
- `src/bmtvd/engine.py`    - MonitorEngine: psutil snapshots (net_io_counters,
  net_connections), rate math (bytes/sec deltas), rolling history, JSON
  serialize/restore for import.
- `src/bmtvd/reporting.py` - history/summary report dict -> TXT/JSON/CSV/HTML/PDF.
- `src/bmtvd/theme.py`     - dark QSS theme.
- `src/bmtvd/main.py`      - PySide6 GUI: dashboard cards, live chart, per-interface
  table, history tab with chart, File > Import History (JSON), File > Export Report.
- `sample_data/history_workday.json` - importable snapshot history (60s interval).
- `tests/smoke_gui.py`     - engine capture + reports + import + GUI (offscreen Qt).

## How to run
```
cd "07. Bandwidth monitor & traffic visualizer dashboard"
python src/bmtvd/main.py          # GUI
python tests/smoke_gui.py         # smoke test
```

## Verified
- Live snapshots produce sane upload/download rates and connection counts on Windows.
- 5 report formats written from both live data and imported history.
- sample_data/history_workday.json imports, charts and exports cleanly.
- GUI boots offscreen; cards and charts initialize without a display.

## Notes
- psutil is the only non-Qt runtime dependency; it is declared in the exe build.
- Rate math guards the first snapshot (no delta yet) and clock jitter.
