# SentinelHIDS — Host-based Intrusion Detection Agent

A self-contained, GUI-based HIDS combining **File Integrity Monitoring (FIM)** and a
**Process Monitor** with a rule-based detection engine. Pure Python + Tkinter; all
state lives in a portable `data/` folder next to the executable.

> Full design: see [`architecture.md`](architecture.md). Project status: [`state.md`](state.md).

## Features

| Area | Capability |
|---|---|
| **FIM (real-time)** | **Instant detection** via watchdog OS notifications (ReadDirectoryChangesW on Windows): created/modified/deleted/moved files alerted within ~1 s of the last write, with debounce coalescing and 30 s alert dedup |
| **FIM (sweep)** | SHA-256 baseline of monitored folders/files; quick (size+mtime) & full verification modes as a periodic safety net; baseline auto-converges |
| **Ransomware heuristic** | Sliding-window burst detector: ≥ N file changes in M seconds → CRITICAL alert (configurable, cooldown-gated) |
| **Process monitor** | psutil telemetry (PID, PPID, user, CPU/RAM, path, cmdline, parent) every N seconds; suspicious rows highlighted; inspect & kill from the GUI |
| **Detection rules** | Known offensive tools (mimikatz, nc, chisel…), encoded/hidden PowerShell, Office→shell dropper chains, execution from temp dirs, system-process impersonation, Run-key/schtasks persistence |
| **Alerting** | 5-level severities, SQLite-backed history, ack/delete, filter + search, CSV/JSON export |
| **Self-protection** | Baseline DB fingerprint checked at startup → CRITICAL alert on tampering |
| **Ops** | Rotating file log (`data/hids.log`), alert retention pruning, config tuning UI |

## Quickstart (dev)

```bash
pip install -r requirements.txt
python run.py            # or: python -m hids
```

1. **File Integrity** tab → add folders to monitor → **Build / Rebuild Baseline**.
2. Toolbar → **▶ Start Monitoring** (real-time FIM starts watching immediately;
   process polling starts too; the sweep scan runs on the configured interval as a
   safety net — the status bar shows `Real-time FIM: ON`).
3. Modify files under a monitored path or run something suspicious → alerts appear
   **instantly** in **Dashboard** / **Alerts**.

> Tip: disable the real-time engine in **Settings** if you want classic
> interval-only behavior. Changing monitored paths requires restarting monitoring
> so the OS watches can be re-bound.

## Tests

```bash
python -m pytest tests/ -v
```

31 headless tests cover the database layer, FIM detection/burst logic, the
real-time monitor (debounce, filtering, watchdog-missing fallback, a **live
end-to-end observer test**), process rules truth table, exclusion matching and
engine lifecycle.

## Build the portable exe

```bat
build_exe.bat
```

Produces **`dist\SentinelHIDS.exe`** (one-file, no console). Copy it anywhere —
on first run it creates a sibling `data\` folder (config, `hids.db`, logs). If the
host directory is read-only it falls back to `~\.hids-agent\data\`.

> **AV/SmartScreen note:** unsigned PyInstaller one-file builds frequently trigger
> heuristic warnings — expected for security tooling. Distribute signed
> (signtool) or zipped with this README.

## Configuration

`data/config.json` (also editable in the **Settings** tab): real-time FIM toggle
and debounce seconds, sweep interval, process poll interval, max hashed file size,
exclusion patterns (fnmatch), process blacklist, burst threshold/window/cooldown,
alert retention, per-rule alert cooldown.

## Limitations (v1.1)

- Real-time watching binds monitored roots when monitoring starts — path changes
  need a monitoring restart (sweep picks them up immediately).
- A user-mode agent can be stopped by an administrator — run as a service for
  higher assurance.
- Unsigned binaries may be flagged by AV.

## License / disclaimer

Educational/internal use. Run only on systems you are authorized to monitor.
