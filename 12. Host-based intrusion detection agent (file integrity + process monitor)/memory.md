# Memory — SentinelHIDS

Durable notes for future sessions working on this codebase. Read with `state.md`.

## Product identity

- **SentinelHIDS v1.1.0** — host-based IDS: real-time FIM (watchdog) + sweep FIM +
  process monitor, Tkinter GUI, portable PyInstaller exe. Python 3.9+ compatible
  code (no `X | Y` unions).
- Docs: `architecture.md` (design), `state.md` (progress), this file (knowledge).

## Key design decisions (and why)

1. **Tkinter + ttk** over PySide/customtkinter — zero extra deps → smallest,
   most reliable PyInstaller one-file build; clam theme + custom card styles.
2. **Real-time FIM (v1.1) is the primary detection path**; the interval sweep is a
   deliberate safety net. `RealtimeMonitor` (watchdog) feeds `FimEngine._process_path_now()`
   per debounced path: hash → compare vs baseline → update baseline → deduped alert →
   burst feed. Sweep and realtime share `_emit_single` + a 30 s (path, change) dedup map
   so a change is alerted exactly once even if both paths race.
3. **Polling sweep with quick path** (size+mtime compare, rehash only on mismatch)
   → cheap sweeps; full-rehash is a manual option. `scan_interval_seconds` now means
   sweep interval (default 300 s).
3. **Baseline auto-converges** after every verify (upsert adds/mods, remove deletes)
   — baseline always reflects "last seen truth"; rebuild only for resets.
4. **Ransomware burst detector** = sliding deque of (ts, count) with threshold
   (15/60 s default) + cooldown (300 s), state per-engine — fed by BOTH realtime
   events (1 change each) and sweeps. Tested with injected timestamps.
5. **Engines never touch Tk.** Communication is one-directional via `EventBus`
   (bounded queues, drop-on-full). GUI drains with `after(150)`. Worker→UI calls
   go through `app.ui_call(fn, *args)` → `UI_CALL` event → executed on UI thread.
6. **SQLite per-thread connections** (`threading.local`) + WAL + busy_timeout —
   GUI, FIM thread, process thread share one DB file without lock errors.
7. **Alerts written by engines** (not UI) so detections persist even if GUI dies.
8. **Baseline tamper check**: `meta.baseline_fingerprint` = SHA-256 over all rows;
   recomputed after every build/scan, verified in `HidsApp.__init__` → CRITICAL alert.
9. **Process rules are declarative** (`@rule` decorator in `engines/rules.py`) —
   add a rule = add a function; severities live with the rule.
10. **Alert throttling**: process rules keyed (rule_id, name) with 900 s cooldown;
    burst alert cooldown-gated. Keeps a hostile host from flooding the DB.

## Gotchas learned this session

### watchdog / real-time FIM (v1.1)
- Windows ReadDirectoryChangesW is **natively recursive** — one `observer.schedule()
  per root` covers the whole tree; re-scheduling nested dirs (needed on POSIX inotify)
  would **double-report on Windows** → guard nested scheduling with `sys.platform != "win32"`.
- Editors/compilers fire many events per save; hashing mid-write gives unstable
  digests → **debounce = quiet-period**: `pending` dict path→last-event-ts, worker
  processes after `realtime_debounce_seconds` of silence (worker polls 0.2 s; cheap).
- Realtime and sweep can race on the same file (sweep snapshotted a stale baseline row)
  → 30 s `(path, change)` dedup in `FimEngine._emit_single` is load-bearing.
- Watchdog event paths vs baseline paths must match exactly → all baseline/verify
  paths normalized via `FimEngine._norm()` (normpath+abspath); DB rows and seen-set
  both normalized, otherwise false ADDED alerts from separator mismatches.
- `enqueue()` filters (monitored root prefix via `os.path.normcase`, exclusions)
  **before** the pending dict — garbage never wakes the worker.
- Missing watchdog degrades gracefully: module-level try-import sets
  `WATCHDOG_AVAILABLE=False`; `start()` returns False, worker still runs, sweep covers.
- PyInstaller: add `--collect-submodules watchdog` so platform observers ship in
  the one-file build.

- `r"C:\path\"` is a **syntax error** (raw string can't end in backslash) — use
  forward slashes in patterns; `path_excluded` normalizes `\` → `/` anyway.
- Exclusions must be applied **twice**: prune dirs inside `os.walk` **and** filter
  each yielded file (patterns like `*.log` are file-level; `skipme/` is dir-level).
- `path_excluded` dir-prefix patterns must match as **any path component**
  (`f"/{prefix}/" in f"/{norm}/"`), not just string startswith.
- psutil: resolve parent names from the **snapshot's own pid→name map**, not
  `p.parent()` per process (avoids extra syscalls, much faster).
- psutil `cpu_percent` is 0.0 on first observation — cosmetic only in our GUI.
- PyInstaller onefile spawns **two** processes (bootloader + app) — `taskkill //IM`
  by image name in bash needs `//IM`/`//F` (double slash) escaping.
- Frozen data dir = `Path(sys.executable).parent / "data"`; write-probe fallback
  to `~/.hids-agent/data` if the exe folder is read-only.
- In bash-on-Windows, run `.bat` via `cmd //c build_exe.bat`.

## Commands

| Task | Command |
|---|---|
| Run GUI | `python run.py` or `python -m hids` |
| Tests | `python -m pytest tests/ -v` |
| Build exe | `build_exe.bat` → `dist/SentinelHIDS.exe` |
| Clean rebuild | delete `build/ dist/` then re-run bat |

## Config keys that matter

`realtime_fim=true` · `realtime_debounce_seconds=1.0` · `scan_interval_seconds=300`
(now the SWEEP interval / safety net) · `process_poll_seconds=10` · `max_file_size_mb=100` ·
`burst_threshold=15` / `burst_window_seconds=60` / `burst_cooldown_seconds=300` ·
`process_alert_cooldown_seconds=900` · `alert_retention_days=30` ·
`monitored_paths[]` · `exclude_patterns[]` · `process_blacklist[]` ·
`process_rules.alert_on_new_process=false`

## File map additions (v1.1)

```
hids/engines/realtime.py   # RealtimeMonitor: watchdog handler, debounce worker,
                           # relevance filter, graceful no-watchdog fallback
hids/engines/fim.py        # + _process_path_now() instant verify, _emit_single()
                           # dedup, _norm() path normalization, realtime lifecycle
tests/test_realtime.py     # 5 tests incl. live end-to-end observer test
```

## Storage layout (runtime)

```
data/
├── config.json      # settings (defaults-merged; corrupt file → safe defaults)
├── hids.db          # SQLite WAL: baseline, alerts, scans, meta
├── hids.db-shm/-wal # WAL sidecars (normal)
├── hids.log         # rotating, 1 MB × 5
└── exports/         # alert CSV/JSON exports (created on demand)
```

## File map (source of truth)

```
hids/core/{config,models,database,events,utils}.py   # headless core
hids/engines/{fim,realtime,process_monitor,rules}.py # detection threads + realtime
hids/gui/main_window.py                              # HidsApp shell + event pump
hids/gui/tabs/{dashboard,fim_tab,process_tab,alerts_tab,settings_tab,logs_tab}.py
hids/gui/widgets.py                                  # StatCard, make_tree, colors
tests/                                               # 31 pytest tests (headless)
build_exe.bat, requirements.txt, run.py, .gitignore
```

## DB schema quick reference

- `baseline(path PK, size, mtime, sha256, first_seen, last_seen, status)`
- `alerts(id, timestamp, severity, category, event_type, title, details JSON, acknowledged)`
- `scans(id, started, finished, files_scanned, modified, added, deleted, errors, duration)`
- `meta(key, value)` — `baseline_built`, `baseline_count`, `last_scan`, `baseline_fingerprint`
