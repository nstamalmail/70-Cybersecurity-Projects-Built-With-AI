# Project State — SentinelHIDS

_Last updated: 2026-09-07 · Version 1.1.0 · Status: **Real-time FIM shipped, verified**_

## Completed

- [x] `architecture.md` — full design (components, data flows incl. real-time FIM,
      schema, rules, packaging, roadmap)
- [x] Core layer: `config.py`, `models.py`, `database.py` (SQLite/WAL, thread-local conns),
      `events.py` (pub/sub bus), `utils.py` (sha256, exclusions, portable data dir)
- [x] FIM engine: baseline build, quick/full verification sweeps, ADDED/MODIFIED/DELETED
      detection, baseline convergence, **ransomware burst detector** (sliding window + cooldown)
- [x] **v1.1 — Real-time FIM (`engines/realtime.py`, watchdog)**
  - [x] Observer: one recursive watch per monitored dir root (ReadDirectoryChangesW on
        Windows; POSIX nested-dir scheduling guarded by platform check)
  - [x] Debounce worker: quiet-period semantics (default 1 s), coalesces rapid saves,
        avoids hashing mid-write files
  - [x] Instant verification: `_process_path_now()` hashes, compares, updates baseline,
        emits deduped alert, feeds burst detector — change alerts in ~1 s
  - [x] 30 s (path, change) alert dedup shared by sweep + realtime → no double alerts
  - [x] Graceful degradation when watchdog is missing (interval sweeps continue)
  - [x] GUI: `Real-time FIM: ON/off` statusbar chip, Settings toggle + debounce field,
        FIM tab real-time indicator, path-change restart hint in logs
- [x] Process engine: psutil snapshots, pid-diffing, rule evaluation, alert throttling,
      kill action (terminate→kill escalation)
- [x] Rules: BLACKLISTED_PROCESS, SUSPICIOUS_POWERSHELL, OFFICE_SPAWNED_SHELL,
      EXECUTABLE_IN_TEMP, SYSTEM_PROCESS_IMPERSONATION, PERSISTENCE_ATTEMPT
- [x] GUI (Tkinter): Dashboard (KPI cards + severity chart), File Integrity,
      Process Monitor, Alerts (filter/ack/export CSV+JSON), Settings, Logs;
      toolbar start/stop, status bar, 150 ms event pump
- [x] Agent self-protection: baseline fingerprint tamper check at startup
- [x] Logging: rotating file `data/hids.log` + live GUI log stream
- [x] Tests: **31/31 passing** — includes a live end-to-end observer test
      (sweep disabled; modify/add/delete detected via realtime within 10 s timeouts)
- [x] GUI smoke test: boots & closes cleanly (v1.1.0, realtime statusbar present)
- [x] Portable exe: `dist\SentinelHIDS.exe` (~12 MB, PyInstaller one-file, windowed,
      `--collect-submodules watchdog`) — verified frozen run creates `dist\data\`
      next to exe (hids.db, hids.log, config)

## Environment (as verified on this machine)

- Windows 11, Python 3.12.7 (`C:\Users\Msi\AppData\Local\Programs\Python\Python312`)
- psutil 7.2.2, watchdog 7.x (installed this session), PyInstaller 6.22.2, pytest 8.x
- Project root: `E:\AI Masterclass\...\12. Host-based intrusion detection agent…\`

## How to run / build

```bash
python run.py                 # dev GUI
python -m pytest tests/ -v    # tests (31)
build_exe.bat                 # → dist\SentinelHIDS.exe
```

## Pending / Next steps (priority order)

1. **E2E attack simulation** — scripted mimikatz-named dummy + encoded-powershell spawn asserting CRITICAL alerts
2. **Code signing** — signtool cert to silence SmartScreen/AV heuristics on the exe
3. Windows service mode + SYSTEM scheduled-task install; tray icon
4. Sysmon/Event Log ingestion + sigma-style YAML rules (roadmap 1.2)
5. SIEM forwarding (syslog/HTTPS JSON) + webhook notifications
6. Baseline signing (HMAC with passphrase) beyond current fingerprint check
7. Optional: severity weighting per monitored path (critical path → modified file = HIGH)

## Known limitations (documented, accepted for v1.1)

- Real-time watches bind monitored roots when monitoring **starts** — adding/removing
  paths requires a monitoring restart (the sweep sees path changes immediately)
- Files written continuously for longer than the debounce window may hash mid-write;
  the periodic sweep re-checks and corrects
- Watchdog/ReadDirectoryChangesW may drop events under extreme load — the sweep is
  the deliberate safety net (and full-scan mode rehashes everything)
- Unsigned exe may trigger AV/SmartScreen heuristics (expected for HIDS tooling)
- User-mode agent can be killed by an admin (service mode planned)
