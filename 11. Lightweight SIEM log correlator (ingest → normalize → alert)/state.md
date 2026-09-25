# State — Lightweight SIEM Log Correlator

> Source of truth for what exists, what has been verified, and what is next.
> Companion docs: `architecture.md` (design) and `memory.md` (decisions/context).

## Status: IMPLEMENTED (v0.2)

The full pipeline **Ingest → Normalize → Correlate → Alert** with a desktop
GUI, plus a portable Windows executable, is built and verified.

## What exists

| Component | Where | Notes |
|---|---|---|
| Entry point | `main.py` | GUI mode (default) or `--headless`; `--data-dir` / `--config` overrides |
| Config | `siem/config.py` | `config.json` merged over defaults; portable `data/` next to exe (APPDATA fallback) |
| Data models | `siem/events.py` | `RawEvent`, `NormalizedEvent`, `Alert` |
| Normalizer | `siem/normalize.py` | Auto-detect: JSON → Syslog → Common Log → CEF → K=V → plain; severity inference |
| Rules engine | `siem/rules.py` | `regex` / `threshold` / `sequence` rules; group-by; per-(rule,key) cooldown dedup; 6 seed rules |
| Storage | `siem/storage.py` | SQLite WAL: events ring buffer (50k cap), alerts, rules, meta |
| Ingest | `siem/ingest.py` | File tail (rotation-aware, `start_at_end` opt-in), UDP syslog, **Windows Event Log** (`winevt` via wevtutil, tail-only), manual paste |
| Webtail picker | `siem/gui.py` `TailDialog` | Pick a log file → preview last ~30 lines → start tailing live (follow-new-lines default) |
| Pipeline | `siem/pipeline.py` | Bounded queue + single processor thread; alert log file |
| **Outbound notifiers** | `siem/notifiers.py` | stdlib-only webhook / email / syslog replay / echo; wired into `_fire_alert`; isolated failures |
| GUI | `siem/gui.py` | Tabs: Dashboard, Live Events, Alerts, Rules, Sources, Console |
| Smoke test | `tests/smoke_test.py` | Headless end-to-end detections |
| Notifier tests | `tests/test_notifiers.py` | Build, templates, bad-config skipping, fail-safe, echo delivery |
| Build scripts | `build_exe.bat` / `build_exe.sh` | PyInstaller onefile windowed |
| Build output | `dist/SIEMCorrelator.exe` | ~11 MB, verified running |

## Verified (Sep 7, 2026)

- `python tests/smoke_test.py` → **ALL PASS**:
  - Possible Brute Force (threshold 5/60s by host) → 1× high
  - SQL Injection Attempt (regex) → 1× critical
  - Web Scanning / Many 404s (threshold 20/60s by src_ip) → 1× medium
  - Fail-then-Success Login (sequence 120s) → 1× high
  - Privilege Escalation / sudo Failure (regex) → 1× high
  - Benign lines → **no false positives**; dedup → exactly 1 alert per rule
- `python tests/test_ingest.py` → **ALL PASS**:
  - `parse_wevtutil_xml` on UTF-16, namespaced, root-less wevtutil output (2 events)
  - `format_winevt_line` → KVP line normalizes (fields `EventID`/`Level`, severity `ERROR`)
  - File source `start_at_end=True` skips existing content; `=False` ingests it (3/3 lines)
  - winevt bookmark: attach skips backlog, only newer RecordIDs emit, quiet when nothing new
- Live (this machine, Windows): `winevt` source on `Application` channel runs, parses, bookmarks
  (`watching (bookmark #13627)`). Writing test events needs admin (`eventcreate` denied) —
  skipped. `/r:true` rendering falls back cleanly here (RPC 1722 in this session).
- GUI smoke: `App` constructs, runs, and closes cleanly (all 6 tabs); `SourceDialog` +
  `TailDialog` open, type-combo switching works, winevt source added via the real pipeline.
- `python main.py --headless --data-dir <tmp>` starts with 6 rules enabled and
  creates `siem.db` + `logs/` correctly.
- `dist/SIEMCorrelator.exe` (PyInstaller 6.22.2, Python 3.12.7) launches,
  stays running, and creates its portable `data/` next to the exe.

## How to use

```
Run from source : python main.py            # GUI
                 : python main.py --headless  # no GUI (server/tests)
Build exe        : build_exe.bat             # → dist/SIEMCorrelator.exe
Test             : python tests/smoke_test.py
```

In the GUI: **Sources** tab → Add a file log or paste; **Live Events** →
*Load sample logs* to see detections immediately; **Alerts** → acknowledge /
close; **Rules** → edit or add rules (changes hot-reload the engine).

Data lives in `<app dir>/data/` → `config.json`, `siem.db` (WAL), `logs/alert.log`.

## Default rule set (seeded on first run, editable)

1. Possible Brute Force — threshold 5/60s by host — high
2. SQL Injection Attempt — regex — critical
3. Web Scanning / Many 404s — threshold 20/60s by src_ip — medium
4. Privilege Escalation / sudo Failure — regex — high
5. Fail-then-Success Login — sequence (2 steps, 120s) by host — high
6. Error Spike — threshold 10/60s global — medium
7. Windows Failed Logon (4625) — regex `EventID=4625` — high (new in v0.2, pairs with the `winevt` source)

## Known limitations (v0.1)

- File tailing is poll-based (0.5 s default); fine for desktop/small-server use,
  not for very high-rate logs.
- UDP syslog only (no TLS); unprivileged ports recommended (e.g. 5514).
- Correlation is in-memory — window/sequence state resets on restart and on
  rule edits. Alerts themselves are durable in SQLite.
- The 404/threshold rules assume log timestamps are monotonic-ish per source.
- GUI filter applies to *new* events (not a historical query).
- Headless mode has no alert notifications (console/alert.log only).
- `winevt` (Windows Event Log) source specifics:
  - Windows-only; polls `wevtutil` every `poll_interval` s and fetches the newest 100
    records — if more than 100 events land between polls, the gap is skipped (noted,
    acceptable for a lightweight tool).
  - Tail-only: events written *before* the source attaches are not ingested.
  - Rendering (`/r:true`) can fail in restricted sessions (RPC 1722) — falls back to
    structured EventData only; message text may then be sparse.
  - Reading `Security` may need elevation depending on the audit policy.

## Next steps (candidate backlog)

- [x] Alert outbound notifiers (webhook / email / syslog replay / echo) —
      `siem/notifiers.py`, config `notifiers: [...]`, wired into
      `Pipeline._fire_alert`; stdlib-only, isolated failures.
- [ ] Native Windows Event Log reading (`EvtSubscribe`, push-based) to replace the
      wevtutil polling and close the >100-events-per-poll gap.
- [ ] Persist configured sources so they survive restarts.
- [ ] Alert export (JSON/CSV) and richer alert states (dismissed, notes,
      incident grouping).
- [ ] Retention policy + DB vacuum; per-rule alert volume stats.
- [ ] `--simulate` flag feeding the sample logs at startup.
- [ ] Icon, version metadata, and Inno Setup installer; sign the binary.
- [ ] CI: run `tests/smoke_test.py` + PyInstaller on tag push.
- [ ] More parsers (W3C, LEEF, Windows XML) and prebuilt rule packs (MITRE ATT&CK tags).