# WebFuzzer — Web Application Fuzzer for Input Validation Testing

GUI-based fuzzer (Python + Tkinter) for testing web application input validation:
SQL injection, XSS, command injection, path traversal, SSTI, open redirect, CRLF,
LDAP and NoSQL injection.

> **Authorized use only.** Scan only targets you own or have written permission to test.

## Features

- 6-tab GUI: Target / Payloads / Scan / Findings / Reports / Settings
- Auto-discovery of injection points (query params, headers, cookies, form/JSON bodies)
- 55+ payloads in 9 categories x 6 encodings (URL, double-URL, HTML entities, Base64, %u)
- Detection: SQL errors, reflected XSS w/ context, time-based blind, file-read,
  command output, SSTI evaluation, open redirect, CRLF header, server errors
- Baseline & canary calibration to suppress false positives
- Rate limiting, thread pool, request cap, TLS toggle, proxy support
- SQLite scan history, HTML/CSV/JSON report export
- Manual data upload: import scan configs, payload lists, and pre-collected findings
- **Generate & export a report without scanning** (Reports → Import findings file)
- `state.md` (live) + `memory.md` (append-only project memory)
- Portable single-file Windows exe (PyInstaller, frozen-aware paths)

## Run from source

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python main.py
```

## Sample data (manual upload)

The `samples/` folder ships with ready-made input files:

| File | Purpose | Load it from |
|---|---|---|
| `samples/sample_config.json` | Complete scan configuration | Toolbar → **📂 Import config** |
| `samples/sample_payloads.txt` | Custom payload list | Payloads tab → **⬆ Load payloads from file…** |
| `samples/sample_findings.json` | Pre-collected findings (report without scanning) | Reports tab → **⬆ Import findings file…** |
| `samples/demo_target.py` | Local vulnerable demo app to scan safely | `python samples/demo_target.py` |

Details: [samples/README.md](samples/README.md).

### Report from sample data without scanning

1. Start WebFuzzer → **5. Reports**
2. **⬆ Import findings file…** → pick `samples/sample_findings.json`
3. Click **Yes** when asked to generate the report → choose a folder
4. HTML / CSV / JSON reports are written there (open `webfuzzer_scan_*.html`)

You can also select any scan in the history table and click
**💾 Export HTML/CSV/JSON…** at any time.

## Self-test (headless, no GUI)

Verifies the engine against a local vulnerable server and writes
`selftest_result.txt`:

```bash
.venv/Scripts/python scripts/selftest.py
```

## Build the portable exe (Windows)

```bash
scripts\build_exe.bat        # or: bash scripts/build_exe.sh
```

The build runs the self-test first, then produces `dist/WebFuzzer.exe`
(single file, windowed, no console). The exe self-tests with
`dist\WebFuzzer.exe --selftest`. All runtime files (`state.md`, `memory.md`,
`data/`, `samples/`) are created next to the executable → fully portable folder.

## Docs

- `architecture.md` — detailed technical architecture & detection matrix
- `state.md` — live session state (machine-maintained)
- `memory.md` — append-only project memory

## Layout

```
main.py                    entry point (GUI / --selftest)
app/config.py              frozen-aware paths + bundled samples
app/core/                  models, payloads, mutator, injector, http_client,
                           detector, engine, report
app/storage/database.py    SQLite (scans + findings)
app/utils/                 state.md/memory.md store, settings.json
app/gui/                   theme/widgets, 6 tabs, main window
app/tools/selftest.py      headless verification
samples/                   sample config / payloads / findings / demo target
scripts/                   selftest + build wrappers
```
