# State — Custom Subnet Calculator & VLSM Planner

> Purpose: preserve the current status of the project so any session (human or AI) can resume work without re-discovery. Update this file whenever significant progress is made.

**Last updated:** 2026-09-07

---

## 1. Project Status: ✅ COMPLETE (v1.0.0)

All architecture.md v1 deliverables are implemented, tested and packaged.

| Deliverable | Status | Notes |
|---|---|---|
| `architecture.md` | ✅ Done | Full design, security posture, algorithms, packaging |
| Domain layer (`src/domain/`) | ✅ Done | Pure math; RFC 4632 / RFC 3021 aware |
| Persistence layer (`src/persistence/`) | ✅ Done | Schema-validated JSON + CSV, atomic writes, TXT/CSV export |
| App controller (`src/app.py`) | ✅ Done | Single facade; `UserError` mapping; logging |
| GUI (`src/ui/`) | ✅ Done | Calculator tab, VLSM tab, menu, status bar |
| Entry point (`main.py`) | ✅ Done | `python main.py` |
| Unit tests (`tests/`) | ✅ 109/109 passing | `python -m unittest discover -s tests` |
| CSV import/export | ✅ Done | Segments round-trip; results export; buttons + menu (D14) |
| SVG diagram export | ✅ Done | Address-space map, waste hatching, legend; menu (D15) |
| Dark theme + polish | ✅ Done | Light/dark palettes, View menu toggle (Ctrl+T), persisted config, row striping, accent buttons (D16) |
| Portable exe (`dist/VLSM-Planner.exe`) | ✅ Built & verified | PyInstaller `--onefile --windowed`, launch-tested, 0 errors in log |
| `state.md` / `memory.md` | ✅ Done | This file + design log |

## 2. How to run / build

```bash
# Run from source (needs Python ≥ 3.8 with tkinter)
python main.py

# Run tests (headless, no display needed)
python -m unittest discover -s tests -v

# Rebuild the portable exe
pyinstaller --noconfirm --clean --onefile --windowed \
  --name "VLSM-Planner" --distpath dist --workpath build main.py
```

Build gates: tests must pass before the exe is considered releasable.

## 3. File layout

```
architecture.md          # design + security architecture
state.md                 # this file — project status
memory.md                # design decisions & rationale log
main.py                  # entry point
src/
  app.py                 # AppController (UI <-> domain facade)
  domain/
    models.py            # SubnetInfo, VlsmSegment, VlsmPlan, errors
    calculator.py        # subnet math, division
    vlsm.py              # VLSM allocator (classic contiguous algorithm)
  persistence/
    repository.py        # JSON save/load (validated), TXT export
    csv_io.py            # CSV import/export (segments + results)
    svg_export.py        # SVG diagram of the VLSM allocation
    config.py            # user preferences (theme), per-user app data
  ui/
    main_window.py       # notebook, menu, status bar, theme toggle
    calculator_tab.py    # tab 1
    vlsm_tab.py          # tab 2
    widgets.py           # label grid, clipboard copy helpers
    theme.py             # light/dark palettes, clam styling, row striping
  util/
    logging_setup.py     # rotating file + console logging
tests/
  test_calculator.py     # 28 tests
  test_vlsm.py           # 15 tests
  test_repository.py     # 12 tests
  test_csv_io.py         # 14 tests
  test_app.py            # 15 tests
  test_svg_export.py     # 12 tests
  test_config.py         # 9 tests
  test_theme.py          # 5 tests (GUI-backed)
dist/VLSM-Planner.exe    # portable build (not committed)
build/                   # PyInstaller work dir (regenerable)
```

## 4. Known issues / open items

1. **IPv6 not supported** — v2 candidate (architecture.md §10).
2. **Non-contiguous VLSM mode** (best-fit packing) — deliberately out of scope for v1; classic contiguous allocation is the textbook default.
3. **CSV import tolerates first-row headers only** — a non-numeric hosts column in the first non-blank row is always treated as a header (documented in D14).
4. **Native dialogs stay OS-light in dark mode** — file dialogs and message boxes are system-drawn; only the app chrome is themed (documented in D16).
3. **UI smoke test not automated** — GUI is exercised manually; domain + persistence are covered by 50 automated tests.
4. Logs land in `%LOCALAPPDATA%\VlsmPlanner\logs\vlsm.log` when running the packaged exe, `./logs/` in source mode.

## 5. Next steps (priority order)

- [ ] Manual GUI smoke test on a fresh Windows machine (no Python) using `dist/VLSM-Planner.exe`
- [ ] (v2) IPv6 support: parallel `IPv6Network` code paths in domain + UI selector

## 6. How state.md is meant to be used

- Start every session by reading `state.md` (status + next steps) and `memory.md` (why decisions were made).
- On completion of a task, update both files: status here, decisions/rationale there.
- Never delete the file; rewrite sections in place to keep a single source of truth.