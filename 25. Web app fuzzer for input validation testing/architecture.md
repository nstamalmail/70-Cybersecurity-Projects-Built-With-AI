# WebFuzzer — Web Application Fuzzer for Input Validation Testing

**Document type:** Technical Architecture
**Author:** Senior Security Developer
**Version:** 1.0
**Status:** Implemented (see `state.md` for live status)

---

## 1. Purpose & Scope

**WebFuzzer** is a desktop GUI tool for **input validation testing** of web applications.
It automates the injection of fuzzing payloads (SQL injection, XSS, command injection,
path traversal, SSTI, open redirect, CRLF, LDAP, NoSQL) into user-controlled entry points
(query parameters, path segments, headers, cookies, form/JSON bodies) and analyzes
responses to detect validation weaknesses.

### In scope
- Parametric fuzzing of a single target host (scope-locked).
- Detection: reflection/context, error signatures, time-based blind, file-read
  signatures, computed template output, open redirects, CRLF header split, server errors.
- SQLite persistence of scan history and findings.
- HTML / CSV / JSON report export.
- Portable single-file Windows executable (PyInstaller `--onefile --windowed`).
- Durable `state.md` (live session) and `memory.md` (append-only project memory).

### Out of scope (v1)
- Crawling / site discovery (spider). Injection points are user-defined or auto-discovered
  from the target request.
- Raw-socket transport (needed for reliable CRLF header injection — the `requests`
  library blocks control characters client side).
- Authentication flows (OAuth, MFA), WAF evasions beyond encoding transformations.
- Exploitation / shell access. This tool reports *evidence of validation weaknesses* only.

### Authorized-use gate
The tool is intended for **authorized** testing only (your own app, CTF labs, or targets
you have written permission to test). The GUI requires an explicit confirmation checkbox
before every scan, and the scan is **host-locked** to the target origin.

---

## 2. High-Level Architecture

```
                        +------------------------------------------------------+
                        |                   GUI LAYER (Tkinter)                |
                        |  Toolbar | Target | Payloads | Scan | Findings |     |
                        |  Reports | Settings tabs                              |
                        +----------------------------+-------------------------+
                                                     |  event queue
                                                     v
                        +------------------------------------------------------+
                        |              CONTROLLER (WebFuzzerApp)               |
                        |  gather config -> FuzzEngine -> poll events -> UI    |
                        +----------------------------+-------------------------+
                                                     |
                                                     v
                        +------------------------------------------------------+
                        |                 CORE ENGINE (thread pool)            |
                        |   Injector -> HttpClient -> Detector                 |
                        |   (payload x encoding x injection point)             |
                        +------+-----------+----------------+------------------+
                               |           |                |
                               v           v                v
                       +-----------+ +----------+ +---------------------+
                       |  SQLite   | | HTML/CSV | | state.md / memory.md |
                       |  scans.db | | JSON rep | | StateStore           |
                       +-----------+ +----------+ +---------------------+
```

**Threading model.** Tkinter is not thread-safe. All UI mutation happens on the main
thread. Workers (the engine and its `ThreadPoolExecutor` fuzzing tasks) push *events*
(`finding`, `progress`, `log`, `status`, `scan_started`, `scan_finished`) onto a
`queue.Queue`; the main loop polls it with `root.after()` and applies state to widgets.

---

## 3. Module Map

```
main.py                          Entry point; runs GUI or --selftest.
app/config.py                    APP_NAME, VERSION, base/data dir resolution (frozen-aware).
app/core/models.py               Dataclasses: InjectionPoint, ScanConfig, Finding, RequestSpec.
app/core/payloads.py             Payload DB (9 categories, 55 payloads) + technique hints.
app/core/mutator.py              Encoders: None/URL/Double-URL/HTML entities/Base64/%u unicode.
app/core/injector.py             Builds concrete requests per injection point; auto-discovery.
app/core/http_client.py          requests wrapper: thread-local sessions, rate limiter, error mapping.
app/core/detector.py             Response analysis -> Finding list (see detection matrix).
app/core/engine.py               FuzzEngine orchestrator: plan, baseline, canary, pool, events.
app/core/report.py               HTML/CSV/JSON report generation from scan findings.
app/storage/database.py          SQLite access layer (scans + findings).
app/utils/state.py               StateStore: state.md (live) + memory.md (append log).
app/utils/settings.py           settings.json persistence (GUI remembers last configuration).
app/tools/selftest.py            Headless self-test: local vulnerable server + engine assertions.
app/gui/widgets.py               Dark theme (ttk clam) + reusable widgets.
app/gui/main_window.py           App controller, toolbar, event loop, wiring.
app/gui/*_tab.py                 Target / Payloads / Scan / Findings / Reports / Settings tabs.
samples/                         Sample data: config, payload list, findings JSON,
                                 demo target app (manual-upload input data).
scripts/selftest.py              CLI wrapper for headless self-test.
scripts/build_exe.sh, build_exe.bat   Reproducible PyInstaller build.
```

---

## 4. Data Model

```
InjectionPoint { kind: query|path|header|cookie|body_form|body_json|body_raw
               | name | value | enabled }
ScanConfig     { target_url, method, headers{}, cookies{}, body, body_type,
               | injection_points[], categories[], encodings[], custom_payloads[],
               | threads, delay_ms, timeout, follow_redirects, verify_ssl, proxy,
               | max_requests, time_based, max_body_analysis }
RequestSpec    { url, method, headers, cookies, body, timeout, allow_redirects,
               | verify, proxies }        + preview() -> plain-text HTTP request
Finding        { id, ts, category, technique, severity, injection_kind, injection_name,
               | payload, encoding, url, status, resp_len, resp_time_ms, evidence,
               | request_preview, response_snippet }
```

**Severity ladder:** `critical > high > medium > low > info`.

---

## 5. Scan Pipeline

1. **Validate & plan.** Check URL scheme/host, ≥1 enabled injection point, ≥1 category or
   custom payload. Build the task list: `IPs × categories × payloads × encodings`
   (+1 canary per IP, +1 baseline request per IP). Truncate at `max_requests`.
2. **Baseline.** For each injection point send the request with its *original* value.
   Store `(status, elapsed, body-text)` as the comparison baseline.
3. **Canary.** Send a unique marker (`wfz<hex>`). Log whether the parameter is reflected
   and in which context — informs the human and calibrates later reflection findings.
4. **Fuzz.** Submit tasks to a `ThreadPoolExecutor` (configurable workers). Each worker:
   wait-pause → rate limit → build request → send → analyze → emit findings → write
   findings to SQLite → return counts.
5. **Stop / pause semantics.** A shared `threading.Event` is checked before every
   request; pause loops until resumed; stop cancels pending futures (workers drain fast).
6. **Finalize.** Update scan row (requests, errors, findings, duration), write
   `state.md`, append to `memory.md`, emit `scan_finished`.

---

## 6. Detection Matrix

| Technique | Trigger | Severity |
|---|---|---|
| `xss-reflection` | Payload found verbatim in body; context = attribute/script/html; unencoded specials (`<`, `"`) → high; encoded → low | high / low |
| `sql-error` | Known DB error signatures (MySQL/Postgres/MSSQL/SQLite/ODBC) | high (SQLi) / medium |
| `time-based-blind` | Payload contains `sleep(/WAITFOR` and `elapsed >= baseline + 4s` | high |
| `file-read` | `root:x:0:0`, `[fonts]`, boot.ini markers in body **and not in baseline** | critical |
| `cmd-output` | `uid=NNN(`, `nt authority\`, passwd/win.ini markers | high |
| `ssti-eval` | Expected computed output (`{{7*7}}` → `49`) present, absent from baseline | high |
| `open-redirect` | 3xx + Location pointing at attacker-controlled host (`//evil…`, `https://evil…`) | medium |
| `crlf-header` | Injected header (`X-Injected`) present in response headers | medium |
| `server-error` | 5xx triggered vs non-5xx baseline | low |
| `reflection-info` | Reflection of non-XSS payloads (verbatim) | info |

**Anti-noise controls.**

- File-read / SSTI / cmd-output findings are only reported when the signature is
  **absent from that injection point's baseline body**.
- Time-based detection compares against the baseline request's latency.
- Findings are capped per request (≤3) and per-scan noise notes are surfaced in the log.

---

## 7. Concurrency, Rate Limiting & Resilience

- **Workers:** `ThreadPoolExecutor(max_workers=threads)`, one `requests.Session` per
  thread (thread-local) to avoid cross-thread cookie races.
- **Rate limiting:** global `RateLimiter` (mutex + min interval `delay_ms`), applied
  uniformly across workers so the scan cannot exceed a set request rate.
- **Timeouts:** connect/read timeout per request; `time_based` scans require a generous
  timeout (recommend ≥10s).
- **Errors:** per-request exception mapping (`InvalidURL`, `ConnectionError`,
  `Timeout`, TLS errors) → logged, counted as `errors`, never crash the scan.
- **Scope lock:** requests are only ever built against the target origin from the UI
  config; the engine additionally validates the final URL host == target host.

---

## 8. Persistence

### SQLite (`data/webfuzzer.db`)
```sql
CREATE TABLE scans      (id INTEGER PRIMARY KEY, started_at TEXT, finished_at TEXT,
                         target TEXT, config_json TEXT, total_requests INTEGER,
                         findings_count INTEGER, errors INTEGER);
CREATE TABLE findings   (id INTEGER PRIMARY KEY, scan_id INTEGER, ts TEXT, category TEXT,
                         technique TEXT, severity TEXT, injection_kind TEXT,
                         injection_name TEXT, payload TEXT, encoding TEXT, url TEXT,
                         status INTEGER, resp_len INTEGER, resp_time_ms REAL,
                         evidence TEXT, request TEXT, response TEXT);
```

### `state.md` — live session state
Overwritten (throttled) by the engine/UI with: current target, scan progress,
request/finding counters, last findings summary, timestamp. Allows any later session
(including an AI agent) to see exactly where the last scan left off.

### `memory.md` — append-only project memory
`StateStore.log_memory()` appends timestamped events: app start/exit, scan started/
finished, findings (severity-aware one-liners), report exports, errors. It is the
durable project memory that persists across sessions; owners can append design
decisions and lessons learned.

### `settings.json` — last-used GUI configuration
Persisted on scan start and app close (authorization checkbox is intentionally
**not** persisted — it must be re-confirmed every session).

### `samples/` — manual-upload input data
User-editable input files that remove the need to hand-type configuration or
even run a live scan. In the frozen exe the bundled copies are unpacked next to
the executable on first run (`ensure_samples_dir()` in `app/config.py`), so the
exe folder stays self-contained and the files stay editable.

| File | Consumed by |
|---|---|
| `sample_config.json` | Toolbar → *Import config* (`WebFuzzerApp._apply_config_doc`) |
| `sample_payloads.txt` | Payloads tab → *Load payloads from file…* |
| `sample_findings.json` | Reports tab → *Import findings file…* (creates a scan row + findings in SQLite, then offers immediate HTML/CSV/JSON export) |
| `demo_target.py` | Standalone vulnerable local target (`python samples/demo_target.py`) |

The findings-import path accepts `{"scan": {...}, "findings": [...]}` documents
or a bare JSON list. Unknown severities downgrade to `info`; missing numeric
fields default to 0. Imported scans appear in the normal scan history and are
exported like any other scan.

---

## 9. Packaging Strategy

- **Runtime:** CPython + `requests` only; GUI is stdlib `tkinter` (no heavyweight GUI
  framework → small portable exe).
- **Build:** PyInstaller `--onefile --windowed --name WebFuzzer main.py` via a pinned
  venv (`requirements.txt` + `requirements-dev.txt`).
- **Portability:** frozen-aware paths — everything (`state.md`, `memory.md`, `data/`,
  `settings.json`) lives **next to the executable**, so the exe folder is fully
  self-contained and portable (USB, VM, analyst workstation).
- **Headless verification in the exe:** `WebFuzzer.exe --selftest` runs the engine
  against a local in-process vulnerable server and writes `selftest_result.txt`
  next to the exe — proving the one-file bundle works end to end.

---

## 10. Extension Points

1. **Payload DB** (`payloads.py`) — add categories/entries; each entry = `(payload, technique)`.
2. **Encoders** (`mutator.py`) — add an encoder function and register it in `ENCODINGS`.
3. **Detectors** (`detector.py`) — add a check returning `(severity, technique, evidence)`;
   baseline plus response are both available.
4. **Injectors / discovery** (`injector.py`) — add a new `InjectionPoint.kind`.
5. **Reports** (`report.py`) — add exporters.
6. **Custom payloads** via the GUI text area (category `Custom`, any encoding).

---

## 11. Security & Safety Controls

- Explicit authorization gate before each scan; never persisted.
- Host-locked scope (single origin), no follow-into-elsewhere links.
- Global rate limiting + `max_requests` cap → no unintentional DoS.
- Detectors use baseline-relative checks (no false "file read" from normal content).
- No credentials are stored; cookie values live only in memory and in the DB (user opts in).
- All analysis runs locally; no telemetry / network calls beyond the scan target.

---

## 12. Build & Run

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt -r requirements-dev.txt
.venv/Scripts/python scripts/selftest.py            # engine verification (headless)
.venv/Scripts/python -m PyInstaller --noconfirm --clean --onefile --windowed \
    --name WebFuzzer \
    --add-data "samples;samples" main.py
dist/WebFuzzer.exe --selftest                       # verify the portable exe
```

`--add-data` bundles the `samples/` folder inside the exe; on first run the
files are unpacked next to the executable so the user can edit or replace them.
The `scripts/build_exe.*` wrappers pass this flag automatically.

---

## 13. Testing Strategy

- **Headless engine test** (`scripts/selftest.py`): local `ThreadingHTTPServer` with
  echo/SQLi/traversal/SSTI/redirect/command/sleep endpoints; asserts that canonical
  techniques are detected, `state.md`/`memory.md` are maintained, and scan lifecycle
  events all fire.
- **GUI smoke:** instantiate `tk.Tk` + app in CI/desktop; manual checklists for each tab.
- **Packaging test:** `--selftest` inside the frozen exe.

---

## 14. Roadmap

- Raw-socket transport for true CRLF/header splitting and HTTP/1.0 tricks.
- Boolean-based blind SQLi differential detection (truthy/falsy response pairs).
- Request templates from captured traffic (Burp/Chrome HAR import).
- Response-structure diffing (HTML normalization) to cut reflection noise.
- Custom placeholders (`{FUZZ}`) in headers/raw body, multi-position fuzzing.
- Detector scoring / triage dashboard and per-severity export filters.