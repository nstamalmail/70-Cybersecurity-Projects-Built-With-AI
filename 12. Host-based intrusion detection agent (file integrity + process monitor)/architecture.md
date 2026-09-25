# SentinelHIDS — Architecture Document

**Product:** Host-based Intrusion Detection Agent (File Integrity Monitoring + Process Monitor)
**Version:** 1.1.0 | **Status:** Implemented | **Author:** Security Engineering
**Stack:** Python 3.9+, Tkinter (GUI), SQLite (storage), psutil (process telemetry), watchdog (real-time FIM), PyInstaller (portable exe)

---

## 1. Overview

SentinelHIDS is a local, self-contained host intrusion detection agent for Windows
(cross-platform capable). It combines two classical HIDS disciplines:

1. **File Integrity Monitoring (FIM)** — cryptographic baselining and verification of
   critical files/directories (system binaries, configs, web roots, scripts) to detect
   unauthorized modification, deletion, or planting of files — delivered through
   **real-time OS notifications (watchdog/ReadDirectoryChangesW)** plus a periodic
   sweep scan as safety net, including **ransomware-like mass-modification bursts**.
2. **Process Monitoring** — periodic endpoint telemetry (process tree, paths, command
   lines, users) evaluated against a rule engine that flags known attacker tooling,
   LOLBin abuse, office-app dropper chains, temp-directory execution, system-process
   impersonation, and persistence attempts.

### Goals
- G1: Single portable `.exe`, no installation, no external services.
- G2: All state (baseline, alerts, config, logs) stored **next to the executable**
  (`./data/`) so the agent is fully portable (USB-runnable).
- G3: Low false-positive rate — rules are conservative; noisy signals are throttled.
- G4: Non-blocking GUI — engines run on background threads; UI never freezes.
- G5: Tamper awareness — the agent detects modification of its own baseline.

### Non-Goals (v1)
- Real-time kernel minifilter / ETW telemetry (see §11 Roadmap).
- Network intrusion detection, SIEM forwarding (planned: JSON syslog out).
- Central management server.
- Self-defense against process termination (documented limitation).

---

## 2. System Context

```
                    ┌──────────────────────────────────────────────┐
                    │              SentinelHIDS.exe                │
                    │  ┌────────────────────────────────────────┐  │
   User interacts ──┼──►  GUI (Tkinter) 6 tabs + status bar       │  │
                    │  └───────▲────────────────────────────────┘  │
                    │          │ events (queue, 150ms pump)        │
                    │  ┌───────┴─────────────┐                     │
                    │  │   Application Core  │                     │
                    │  │ Config • Database   │                     │
                    │  │ EventBus • Utils    │                     │
                    │  └───────▲──────▲──────┘                     │
                    │          │      │                            │
        ┌───────────┼──────────┘      └───────────┐                │
        │           │                             │                │
        │  ┌────────┴─────────┐        ┌──────────┴───────────┐    │
 File │  │    FIM Engine    │        │  Process Engine      │    │
system│  │ baseline/verify  │        │ psutil snapshot +    │    │
 <────┼──┤ SHA-256 + burst  │        │ rule evaluation      │    │
        │  └────────┬─────────┘        └──────────┬───────────┘    │
        │           │                             │                │
        │        ┌──▼─────────────────────────────▼───┐            │
        │        │   SQLite  ./data/hids.db (WAL)     │            │
        │        │   baseline • alerts • scans • meta │            │
        │        └────────────────────────────────────┘            │
        │        ./data/config.json • ./data/hids.log • exports/   │
        └──────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Package Layout

```
hids/
├── __main__.py              # CLI entry (argparse, --version) → GUI
├── core/
│   ├── config.py            # JSON config, defaults, data-dir resolution
│   ├── models.py            # Alert, FileRecord, ChangeRecord, ProcessInfo
│   ├── database.py          # SQLite store (thread-local connections, WAL)
│   ├── events.py            # Thread-safe pub/sub EventBus (queue per subscriber)
│   └── utils.py             # sha256_file, path_excluded, app_root, ts_str…
├── engines/
│   ├── fim.py               # FimEngine  (thread): baseline, verify, burst detection
│   ├── realtime.py          # RealtimeMonitor: watchdog observer + debounce worker
│   ├── process_monitor.py   # ProcessEngine (thread): snapshot diff + alerts
│   └── rules.py             # Declarative process detection rules
└── gui/
    ├── main_window.py       # HidsApp(tk.Tk): shell, toolbar, event pump, statusbar
    ├── widgets.py           # StatCard and shared widgets
    └── tabs/
        ├── dashboard.py     # KPI cards, severity chart, recent alerts
        ├── fim_tab.py       # monitored paths, baseline build, verify, results
        ├── process_tab.py   # live process table, inspect, kill
        ├── alerts_tab.py    # filter/search/ack/export alerts
        ├── settings_tab.py  # tuning, exclusions, retention
        └── logs_tab.py      # live engine log stream
run.py                       # dev entry:  python run.py
tests/                       # pytest suite for core + engines
build_exe.bat / hids.spec    # PyInstaller portable build
```

### 3.2 Layers & Dependencies

| Layer | Modules | Depends on | Rule |
|---|---|---|---|
| GUI | `gui/*` | core, engines (control only) | No direct engine internals; engines expose `start/stop/verify/snapshot` |
| Engines | `engines/*` | core, psutil, watchdog | Never touch Tk — communicate **only** via `EventBus` |
| Core | `core/*` | stdlib, psutil (utils) | Pure logic, 100% unit-testable headless |

---

## 4. Data Flow

### 4.1 Baseline Build (FIM)
```
User picks monitored paths → FimTab "Build Baseline"
  → FimEngine.build_baseline() [worker thread]
     → os.walk each path, apply exclude_patterns (fnmatch, pruned at dir level)
     → sha256_file() chunked hashing (1 MiB), skip files > max_file_size_mb
     → db.replace_baseline(records)   (single transaction)
     → db.set_meta(baseline_built, baseline_count)
  → events: scan_progress(done,total) … scan_finished(stats)
```

### 4.3 Real-Time FIM (watchdog) — primary detection path
```
watchdog Observer: one recursive watch per monitored dir root
   (Windows: ReadDirectoryChangesW; POSIX: inotify + nested-dir scheduling)
  → filesystem event (created / modified / deleted / moved)
  → RealtimeMonitor.enqueue(path)
       filter: inside monitored root?  not excluded?  not a directory?
  → pending dict: path -> last-event timestamp  (rapid saves coalesce)
  → worker thread: after realtime_debounce_seconds of quiet (default 1 s)
       → FimEngine._process_path_now(path):
            hash file, compare with baseline
            ADDED / MODIFIED / DELETED → update baseline → alert (deduped)
            feed burst detector
```
Design notes:
- **Debounce (quiet-period) semantics** — editors/compilers emit many events per
  save; a path is hashed only after it stops changing. Avoids hashing mid-write.
- **Alert dedup** — `_emit_single` suppresses duplicate (path, change) alerts
  within 30 s, eliminating sweep/realtime races and watchdog double-fires.
- **Graceful degradation** — watchdog missing or no watchable root ⇒ interval
  sweep remains the detection path (worker still runs, observer simply absent).
- Path changes require restarting monitoring (observer binds roots at start).

### 4.4 Periodic Sweep (safety net) — was the v1.0 primary path
```
Timer loop (scan_interval_seconds, default 300s) or manual "Verify Now"
  → db.start_scan() → scan row
  → for each discovered file:
       quick check: size + mtime match baseline?  ──yes──► skip (fast path)
            │ no
       rehash SHA-256 → compare to baseline hash
       ADDED  (not in baseline)      → ChangeRecord
       MODIFIED (hash differs)       → ChangeRecord
       DELETED (baseline file gone)  → ChangeRecord
  → db.upsert_baseline / remove_baseline (baseline converges to current truth)
  → per-change Alert(severity by type & path criticality) → db + EventBus
  → burst detector: ≥ burst_threshold changes within burst_window_seconds
       → CRITICAL "Ransomware-like mass modification" alert (cooldown-gated)
  → db.finish_scan(stats) → EventBus scan_finished
```

### 4.5 Process Poll
```
ProcessEngine loop (process_poll_seconds, default 10s)
  → psutil.process_iter(...) snapshot (NoSuchProcess/AccessDenied tolerated)
  → parent name resolved from pid→name map (no per-process parent() cost)
  → rules.evaluate_process(pi, blacklist) → [(rule_id, severity, reason)]
  → suspicious processes: Alert → db + EventBus (throttled per rule+name, 15 min)
  → optional INFO alert on every new PID (config, default OFF)
  → EventBus process_snapshot(procs) → GUI table refresh
```

### 4.6 Event Pump (GUI)
```
Engines post (kind, payload) → EventBus → per-subscriber Queue
GUI: after(150ms) drains queue:
   alert            → Alerts tab insert + Dashboard counters/chart + log stream
   scan_finished    → FIM results tree + baseline stats + statusbar
   process_snapshot → Process tab table (suspicious rows highlighted)
   log              → Logs tab
```

**Threading model:** 1 UI thread + 1 FIM thread + 1 Process thread +
watchdog observer/worker threads (real-time FIM) + short-lived
worker threads for manual scans/snapshots/exports. Stop coordination via
`threading.Event` (`stop.wait(interval)` → instant, interruptible shutdown).
SQLite access is thread-safe via thread-local connections + WAL mode.

---

## 5. Detection Capability Matrix

### 5.1 FIM alerts

| Event | Severity | Notes |
|---|---|---|
| File added (real-time or sweep) | LOW | New file inside monitored scope |
| File modified (real-time or sweep) | MEDIUM | Hash mismatch vs baseline; realtime fires within ~1 s of last write |
| File deleted (real-time or sweep) | MEDIUM | Baseline entry vanished (real-time detects via delete/move events) |
| Mass modification burst | **CRITICAL** | ≥15 changes / 60s (configurable), 5-min cooldown; fed by both realtime events and sweeps |
| Baseline fingerprint mismatch | **CRITICAL** | Baseline DB tampered (checked at startup) |

### 5.2 Process rules (`engines/rules.py`)

| Rule ID | Match | Severity |
|---|---|---|
| `BLACKLISTED_PROCESS` | name in blacklist (mimikatz, lazagne, nc, chisel…) | CRITICAL |
| `SUSPICIOUS_POWERSHELL` | `-enc*` / `encodedcommand` / `-w hidden` / `-nop` in cmdline | CRITICAL |
| `OFFICE_SPAWNED_SHELL` | winword/excel/outlook/wscript parent → cmd/powershell/mshta child | HIGH |
| `EXECUTABLE_IN_TEMP` | image path under %TEMP%, Windows\Temp, /tmp | HIGH |
| `SYSTEM_PROCESS_IMPERSONATION` | svchost/lsass/… running outside System32 | HIGH |
| `PERSISTENCE_ATTEMPT` | cmdline writes Run key / schtasks /create | HIGH |

All thresholds, blacklist, and exclusions are user-tunable in Settings.

---

## 6. Data Model

### 6.1 SQLite schema (`data/hids.db`, WAL)

```sql
baseline(path TEXT PK, size INT, mtime REAL, sha256 TEXT,
         first_seen REAL, last_seen REAL, status TEXT DEFAULT 'ok')
alerts(id INTEGER PK, timestamp REAL, severity TEXT, category TEXT,
       event_type TEXT, title TEXT, details TEXT/*JSON*/, acknowledged INT)
scans(id INTEGER PK, started REAL, finished REAL, files_scanned INT,
      modified INT, added INT, deleted INT, errors INT, duration REAL)
meta(key TEXT PK, value TEXT)   -- baseline_built, baseline_count,
                                -- baseline_fingerprint (tamper check)
```

### 6.2 Config (`data/config.json`, schema-versioned, defaults merged on load)

```jsonc
{
  "scan_interval_seconds": 300,
  "realtime_fim": true,
  "realtime_debounce_seconds": 1.0,
  "process_poll_seconds": 10,
  "max_file_size_mb": 100,
  "monitored_paths": [],
  "exclude_patterns": ["*.tmp", "*/.git/*", "*/node_modules/*", "*/__pycache__/*", …],
  "process_blacklist": ["mimikatz.exe", "nc.exe", …],
  "burst_threshold": 15, "burst_window_seconds": 60, "burst_cooldown_seconds": 300,
  "alert_retention_days": 30,
  "process_rules": { "alert_on_new_process": false }
}
```

### 6.3 Event kinds on the bus
`alert` · `log` · `scan_started` · `scan_progress{done,total}` ·
`scan_finished{stats,changes}` · `process_snapshot{procs}` ·
`status{engine,running}` (fim / fim_realtime / process) · `ui_call`

---

## 7. Storage Locations (portability)

| Artifact | Dev mode | Frozen exe |
|---|---|---|
| Data dir | `<repo>/data/` | `<dir of exe>/data/` |
| Fallback (read-only dir) | `~/.hids-agent/data/` | same fallback |

`utils.app_root()` detects `sys.frozen`. A write-probe at startup redirects to the
home fallback so the exe still works from read-only media.

---

## 8. Agent Self-Protection

1. **Baseline tamper detection** — `meta.baseline_fingerprint` stores a SHA-256 over
   all baseline rows; recomputed after every build/scan and verified at startup.
   Mismatch ⇒ CRITICAL alert `BASELINE_TAMPERED` (attacker editing the DB to hide
   tracks is caught).
2. **Alert flow** — alerts written by engines (not UI), so a frozen/killed GUI does
   not lose detections; engines keep logging to `data/hids.log` (rotating, 1 MB × 5).
3. **Known limitation (documented):** a user-mode agent can be stopped by an admin.
   Mitigation roadmap: run as Windows service / scheduled task SYSTEM.

---

## 9. Packaging (portable exe)

- **PyInstaller 6.x, one-file, windowed:** `build_exe.bat` → `dist/SentinelHIDS.exe`
  (includes `--collect-submodules watchdog` so the platform observer ships in the
  one-file build).
- Runtime layout: exe + sibling `data/` folder = complete portable agent.
- Unsigned exe caveat: SmartScreen/AV may warn (PyInstaller onefile is a common
  heuristic trigger). Distribution recommendation: code-sign (signtool) or ship as
  zip with README; false positives are expected for unsigned HIDS tooling.
- Version resource and console hidden (`--windowed`); logs go to `data/hids.log`.

---

## 10. Testing Strategy

- **Unit (pytest, headless):** database CRUD + tamper fingerprint; FIM
  baseline→modify/add/delete detection + exclusions + burst detector (clock-injected);
  realtime monitor (debounce coalescing, filtering, watchdog-missing fallback,
  instant ADDED/MODIFIED/DELETED verification + dedup) and a **live end-to-end
  observer test** (engine running, sweep disabled, asserts modify/add/delete alerts);
  process rules truth table; utils (`path_excluded`). — 31 tests total
- **Manual smoke:** `python run.py` boots UI; baseline a temp dir, touch files, verify.
- **E2E (planned):** scripted attack simulation (drop mimikatz-named copy, encoded
  powershell spawn) → assert CRITICAL alerts raised.

---

## 11. Roadmap

| Phase | Item |
|---|---|
| ~~1.1~~ ✅ v1.1 | **Real-time FIM via watchdog** — shipped: debounced, deduped, baseline-updating, sweep demoted to safety net |
| 1.2 | Sysmon/Event Log ingestion (Windows), sigma-style rule YAML |
| 1.3 | Syslog/JSON HTTPS forwarding to SIEM; alert webhooks |
| 1.4 | Windows service mode + tray icon; scheduled-task SYSTEM install |
| 1.5 | Code signing, auto-update channel, baseline signing (HMAC w/ passphrase) |
