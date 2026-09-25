# Architecture — Lightweight SIEM Log Correlator

**Version:** 0.2 · **Status:** Implemented (see `state.md`)
**Pipeline:** `Ingest → Normalize → Correlate → Alert` with a desktop GUI.

A lightweight, on-premise SIEM that ingests logs from files (webtail-style
picker), syslog (UDP), **Windows Event Logs** (wevtutil, no pywin32) and manual
paste, normalizes them into a common schema, correlates them against detection
rules, and raises alerts in a desktop GUI — with **zero third-party runtime
dependencies** (Python standard library only). Ships as a portable single-file
Windows `.exe`.

---

## 1. Goals & Non-Goals

### Goals
- **Low footprint**: runs on a laptop or small server; no agents, no services to install.
- **Portable**: one `.exe`, data stored next to it (USB-stick friendly).
- **Practical detections**: brute force, scanning, SQLi, error spikes, fail-then-success sequences.
- **Transparent**: user owns the rules, the storage, and the machine.

### Non-Goals (v0.1)
- No multi-tenant / multi-user model, no RBAC, no agents, no TLS syslog, no
  cloud forwarding, no distributed correlation. Those are extension points
  (see §9).

---

## 2. High-Level Architecture

```
                     ┌────────────────────────────────────────────┐
                     │                 GUI (Tkinter)              │
                     │  Dashboard │ Events │ Alerts │ Rules │     │
                     │  Sources   │ Console                        │
                     └──────▲──────────────▲───────────▲──────────┘
                            │ ui_queue     │           │ direct
                            │ (event/alert │           │ (storage
                            │  log msgs)   │           │  queries)
   ┌──────────┐   raw_q   ┌─┴──────────────┴─┐  alert  ┌┴──────────┐
   │ Ingest   │──────────▶│   Pipeline        │────────▶│ Alert     │
   │ Sources  │ queue.    │ (single processor │          │ Manager   │
   │  • file  │  Queue    │  thread)          │          │ + dedup   │
   │  • UDP   │           │  normalize →      │          └──────────┘
   │  • winevt│           │  correlate →      │
   │  • manual│           │  store            │
   └──────────┘           └────────┬──────────┘
                                   │ SQLite (WAL) — events / alerts / rules
                                   ▼
                          ┌──────────────────┐
                          │  Storage layer   │
                          └──────────────────┘
```

### Threading model (critical for correctness)
- **Ingest threads** (1 per active source) → push `RawEvent` into a bounded
  `queue.Queue` (`raw_q`).
- **Single processing thread** drains `raw_q`, normalizes, correlates, stores,
  and pushes display items onto `ui_q`. All SQLite writes happen here.
- **GUI thread (main)** never touches the pipeline objects directly for live
  data; it polls `ui_q` with `root.after()` and renders. Tkinter widgets are
  **only** touched from the main thread.
- **Shutdown**: `threading.Event` stop flag → sources exit → processor drains →
  threads joined with timeout. SQLite uses `check_same_thread=False` + a lock.

Why one processor thread? Ordering: correlation windows and sequences require
events to be processed roughly in arrival order. A single consumer keeps this
simple and deterministic while still handling thousands of events/sec for a
lightweight tool.

---

## 3. Component Specifications

### 3.1 Ingest Layer
| Source | Type | Behaviour |
|---|---|---|
| File tail | `file` | Polls file every `poll_interval` s, reads only new bytes from the tracked offset. Starts at **end of file** (tail semantics) unless `start_at_end=False`, in which case existing content is ingested first (webtail "from the beginning"). Detects rotation/truncation via `st_size < offset` and inode/device change (`st_ino`, `st_dev`) → reopens and reads the new file from offset 0. Missing file → `missing` status, retries until it appears. |
| Syslog | `udp` | Binds `0.0.0.0:<port>` (default 514, disabled by default; pick an unprivileged port like 5514 if you cannot bind). Receives datagrams, decodes UTF-8 with `errors="replace"`. |
| Windows Event Log | `winevt` | Shells out to `wevtutil qe <channel> /f:xml /c:100 /rd:true` every `poll_interval` s (Windows-only, no pywin32). Parses the XML in-process and **tails**: on attach it bookmarks the newest `EventRecordID` and only emits events with a higher record ID. Each event is rendered as a single Key=Value line (`EventID=4625 Provider=… Computer=… Message=…`) so the normalizer's KVP parser feeds `fields` and existing rules work unchanged. Tries `/r:true` (rendered messages) first and falls back silently when the Event Log RPC refuses it (restricted sessions). Non-Windows hosts report `requires Windows + wevtutil` and idle. |
| Manual | `manual` | GUI "Paste logs" pushes raw lines straight into `raw_q`. |

**Webtail picker** (GUI): the `Tail file…` button opens a dialog that shows the
last ~30 lines of the chosen file (like a webtail UI) before you commit; it
starts a `file` source immediately, defaulting to follow-only-new-lines
(`start_at_end=True`).

Every source emits `RawEvent { ts, source_name, source_type, raw }`. Sources
are user-managed at runtime (add/remove/start/stop from the Sources tab).

### 3.2 Normalize Layer
Auto-detects format per raw line and maps it onto a common schema
(`NormalizedEvent`):

| Field | Type | Meaning |
|---|---|---|
| `ts` | float | Epoch seconds — from the log line when parseable, else receive time |
| `source` | str | Source name the event came from |
| `source_type` | str | `file` / `udp` / `manual` |
| `host` | str | Hostname/IP from the log, else source name |
| `severity` | str | `DEBUG/INFO/WARNING/ERROR/CRITICAL` (parsed or keyword-inferred) |
| `message` | str | **Full raw line** — rules always match against this (predictable) |
| `fields` | dict | Extracted structured fields (`src_ip`, `status`, `user`, JSON keys, CEF extensions…) |
| `raw` | str | Original line (never modified) |

**Parser chain (first match wins):**

1. **JSON** — `json.loads` of the line; keys land in `fields`; a `severity`/`level`/`host` key is honored.
2. **Syslog (RFC3164/5424-lite)** — `^<PRI>Mon DD HH:MM:SS host tag[pid]: msg` and RFC5424 with `-`/timestamps; PRI → severity; tag kept in `fields`.
3. **Common Log / Combined (Apache/Nginx)** — `ip - user [date] "request" status bytes "referer" "ua"` → `fields.src_ip`, `user`, `status`, `bytes`, `referer`, `user_agent`.
4. **CEF** — `CEF:0|Vendor|Product|Ver|SigID|Name|Sev|ext` → `fields` = header + `k=v` extensions; CEF severity 0–10 → mapped.
5. **Key=Value** — extracts `k="v"` / `k=v` pairs into `fields`.
6. **Plain text** — fallback; `message` = the line.

Severity inference when the parser yields none: keyword scan of the line
(`critical|fatal` → CRITICAL, `error|err|fail` → ERROR, `warn` → WARNING,
`debug` → DEBUG, else INFO).

**Security stance:** log content is *untrusted input* — never `eval`'d, never
used in shell commands, never formatted into SQL. Parsers use strict regexes
with full-match anchoring and `try/except` everywhere.

### 3.3 Correlation Engine (Rules)

Rule types:

| Type | Semantics | Fields |
|---|---|---|
| `regex` | Single event matches `pattern` (against `field`, default `message`) → alert immediately | `pattern`, `field` |
| `threshold` | ≥ `threshold` matching events from the same `group_by` key within `window` seconds → alert (then resets the counter for that key) | `pattern`, `field`, `threshold`, `window`, `group_by` |
| `sequence` | Deterministic finite automaton over steps: event matching step *i* advances; matching step 0 restarts; window expiry resets. Full run → alert. Classic fail→success compromise detection. | `steps` (`label|pattern`), `window`, `group_by` |

- `group_by`: `host`, `src_ip`, any field name, or unset → global. Produces the
  alert's `group_key` (used for dedup).
- **Dedup / cooldown**: per `(rule_id, group_key)`, a repeat alert within
  `cooldown` seconds is suppressed. Stops alert storms while keeping each new
  incident visible.
- State (threshold windows, sequence automata) is kept in memory per rule; the
  engine is rebuilt when rules change via `engine.reload_rules()`.

**Default rule set** (seeded on first run, editable in GUI):

| Rule | Type | Severity | Pattern / steps |
|---|---|---|---|
| Possible Brute Force | threshold (5/60s, by host) | high | `failed|invalid|denied` + `password|login|auth` |
| SQL Injection Attempt | regex | critical | `union select`, `' or '1'='1`, `--`, `drop table` |
| Web Scanning / Many 404s | threshold (20/60s, by src_ip) | medium | ` 404 ` |
| Privilege Escalation / sudo failure | regex | high | `sudo|su` + `not in sudoers|incorrect password|denied` |
| Fail-then-Success Login | sequence (120s) | high | fail → success, by host |
| Error Spike | threshold (10/60s) | medium | `error|critical|fatal` |

### 3.4 Alert Manager
`Alert { id, ts, rule_id, rule_name, severity, summary, group_key, count, status, fields }`
- `status` lifecycle: `open → acknowledged → closed`.
- Persisted to SQLite immediately (crash-safe, WAL).
- GUI reactions: new alert row (severity-tagged), Alerts tab flashes, optional
  system beep (`winsound`), console line.
- Alert log lines are also written to `logs/alert.log` for out-of-GUI review.
- **Outbound notifiers** (v0.3, stdlib-only): after an alert is persisted and the
  UI callback is given a chance, the pipeline runs each configured notifier in
  its own `try/except` so one failing notifier cannot kill the pipeline or
  suppress the alert. Built-in kinds: ``webhook`` (HTTP/HTTPS POST + JSON body),
  ``email`` (SMTP, optional TLS/auth), ``syslog`` (forward a single-line
  syslog-like message to another host via UDP/TCP/TLS — useful as a SIEM
  forwarder), and ``echo`` (stdout, dev/tests). Config lives in
  ``config.json`` under ``notifiers: [...]``. See ``siem/notifiers.py``.

### 3.5 Storage Layer (SQLite, stdlib `sqlite3`)
- **`events`** — ring buffer capped at `max_events_kept` (default 50 000), pruned in batches. Columns: `id, ts, source, source_type, host, severity, message, fields(JSON), raw`.
- **`alerts`** — `id, ts, rule_id, rule_name, severity, summary, group_key, count, status, fields(JSON)`.
- **`rules`** — full rule definitions; `steps` stored as JSON.
- **`meta`** — schema/config metadata.
- WAL journal, `synchronous=NORMAL`, single connection + mutex for cross-thread access; all queries parameterized.

### 3.6 GUI (Tkinter, ttk)

| Tab | Contents |
|---|---|
| **Dashboard** | Total events, events/min, open alerts, active sources, enabled rules; 24 h alert-severity bar chart (Canvas). Refreshes 1×/s. |
| **Live Events** | Streaming table (newest first, capped rows), substring filter, auto-trim, Clear, **Paste logs** (manual ingest), **Tail file…** (webtail picker with live preview), **Load sample logs** (demo). |
| **Alerts** | Table with severity tags + status; Acknowledge / Close / Reopen / Details / Refresh. |
| **Rules** | CRUD table; New/Edit dialog (type-aware fields; sequence steps as one `label\|pattern` per line, validated compile). Changes hot-reload the engine. |
| **Sources** | Add/remove `file`/`udp`/`winevt` sources (winevt channel picker: Application/System/Security/…), **Tail file…**, live status, start/stop. |
| **Console** | Ring-buffered (1 000 lines) engine log; alert lines highlighted. |

### 3.7 Config & Data Layout
```
<app dir>/                     # exe dir when frozen, project root from source
├── SIEMCorrelator.exe
└── data/                      # created on first run; APPDATA fallback if unwritable
    ├── config.json            # tuning knobs (queues, limits, beep, syslog port…)
    ├── siem.db                # SQLite (events/alerts/rules/meta)
    └── logs/alert.log         # append-only alert trail
```
`config.json` keys: `raw_queue_size`, `max_events_kept`, `poll_interval`,
`syslog_port`, `syslog_enabled`, `alert_beep`, `max_events_rows`,
`max_alerts_rows`. The optional ``notifiers`` key holds a list of outbound
alert targets (see §3.4 and ``siem/notifiers.py``).

---

## 4. Data Flow (end to end)

```
file/udp/winevt/manual ──▶ RawEvent ──▶ raw_q ──▶ Normalizer ──▶ NormalizedEvent
                                                      │
                                      ┌───────────────┤
                                      ▼               ▼
                                 Storage.insert    CorrelationEngine
                                 (ring-buffer)      (rules + windows)
                                                      │ alert
                                                      ▼
                                              AlertManager
                                              ├─ Storage.insert_alert
                                              ├─ ui_q ("alert", …)   ──▶ GUI Alerts tab + beep
                                              └─ logs/alert.log
```

---

## 5. Security Considerations (as-built)

- Log lines are untrusted: regex parsing only, `errors="replace"`, no eval/shell.
- All SQL via parameterized queries; rule strings stored as data, never executed.
- GUI never blocks the pipeline; bounded queues (`raw_q`) back-pressure sources
  instead of unbounded memory growth.
- Ring buffers bound memory: events table capped, GUI rows capped, console capped.
- Portable exe runs with the **current user's** privileges — no admin required,
  no service installation. (Ops note: onefile exes can trip AV heuristics; see
  `memory.md`.)

---

## 6. Packaging & Build

- Runtime: **Python ≥ 3.8 stdlib only** (tkinter, sqlite3, socket, queue,
  threading, json, re, dataclasses, argparse…).
- Build: PyInstaller `--onefile --windowed` → `dist/SIEMCorrelator.exe`.
- Scripts: `build_exe.bat` (Windows) / `build_exe.sh` (POSIX).

---

## 7. Verification Strategy

1. **Unit-ish smoke test** (`tests/smoke_test.py`, headless): seeds a temp DB,
   feeds crafted log lines (brute force, SQLi, 404 flood, fail→success), asserts
   expected alerts appear with correct severities/group keys.
2. **GUI smoke**: instantiate `App` and auto-close after ~2.5 s to prove widget
   construction.
3. **Manual**: run the exe, Load sample logs, watch alerts.

---

## 8. Extension Points (future)

- Parsers: LEEF, W3C, Sysmon XML, Windows Event XML (native, without KVP round-trip).
- Transports: syslog over TLS, native Windows Event Log API (`EvtSubscribe`, push-based, no wevtutil subprocess), journald, HTTPS collectors.
- Persistence: retention policies, alert export (JSON/CSV), email/webhook
  notifiers (stdlib `smtplib`/`urllib` keeps the zero-dep promise).
- Analytics: baseline deviation (EWMA) rules, event dedup/aggregation charts.
- Packaging: icon, version metadata, Inno Setup installer, signed binaries.

---

## 9. Quick Reference

```
Run from source : python main.py            (GUI)      | python main.py --headless
Build exe       : build_exe.bat  →  dist/SIEMCorrelator.exe
Data            : ./data/  (config.json, siem.db, logs/)
```