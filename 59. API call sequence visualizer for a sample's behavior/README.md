# API Call Sequence Visualizer (ACSV)

A desktop workbench that turns a sandbox behaviour report into a navigable view of
**what a sample did, in what order, and why it matters**. It ingests Cuckoo and
CAPE reports (JSON and CAPE BSON behaviour logs), normalises every API call,
rebuilds the process tree, mines the call sequences, matches them against a
catalogue of behavioural patterns, extracts indicators — and exports the whole
analysis as a report you can download in six formats.

> **Scope:** this tool analyses reports produced by an isolated sandbox. It never
> executes, injects into, or contacts anything. All demo fixtures are synthetic
> and generated in memory.

---

## Quick start

```bash
pip install -r requirements.txt

python run.py                    # GUI
python run.py --selftest         # headless verification of all fixtures + exports
python run.py --demo cape-injection
python run.py --analyze report.json --formats html,pdf,json,csv,md
```

Portable one-file executable:

```bash
python build_exe.py --clean      # -> dist/ACSV-ApiSequenceVisualizer.exe
dist/ACSV-ApiSequenceVisualizer.exe --selftest
```

Everything the tool generates (report copies, `cases.db`, exports, logs,
settings) lives in `data/` next to the executable, falling back to
`%LOCALAPPDATA%\acsv` when that folder is read-only.

---

## What it does

| Stage | Detail |
|---|---|
| **Ingest** | Cuckoo `report.json` (v1/v2), CAPE `report.json`, CAPE `.bson` behaviour logs, normalised JSON Lines. Format is auto-detected. |
| **Normalise** | Every call becomes one record: canonical category, relative timestamp, status, arguments, return value, loop count. Missing categories are inferred from the API name. |
| **Collapse loops** | Runs of identical calls (same process, API, arguments, within 5s) become a single record with a repeat count, so a 10 000-iteration encryption loop reads as one behaviour with `x10000`. |
| **Process tree** | Rebuilt from the report's own tree with `parent_id` fallback, enriched with per-process call counts, category mix and heuristic notes. |
| **Sequence mining** | Frequent n-grams (2–5 steps) and maximal recurring clusters, plus a first-order Markov transition matrix and the highest-probability behaviour paths. |
| **Pattern matching** | 26 ordered behavioural patterns (injection, hollowing, APC, run-key and service persistence, scheduled tasks, dropper chains, beaconing, credential access, shadow-copy destruction, in-place encryption, mass-rename, anti-debug, security-stack tampering, discovery, packing/self-modifying memory) with a bounded gap between steps and a span cap. |
| **Scoring** | 0–100 behaviour score and a severity band derived from matched patterns, tag weight and failure ratio. |
| **Indicators** | URLs, IPs, domains, file paths, registry keys, mutexes, services and command lines pulled from call arguments and the report's `behavior.summary`. |
| **Report** | HTML, PDF, JSON, CSV, IOC-only CSV and Markdown — from the **Report & Export** tab, the File menu, or `--formats all`. |
| **Case store** | Each run is appended to `data/cases.db` (runs, calls, findings, indicators) so samples can be pivoted later. |

---

## The interface

| Tab | Purpose |
|---|---|
| **Ingest** | Pick a report, run a synthetic fixture, tune analysis options, see recent runs. |
| **Overview** | Verdict and KPI strip, narrative summary, category chart, report metadata, and a tactic matrix of matched patterns (click a cell to jump to the finding). |
| **Timeline** | Call-rate chart, shared event strip (findings + bursts), burst table, busiest windows by category. |
| **Call sequence** | The core view: filter by process, category, API, argument text, failure, repeat count, suspicion and time window; inspect full argument evidence, and double-click a mined motif to filter the table to it. |
| **Patterns** | Every finding with its matched calls, plus the complete pattern catalogue with step sequences, gap and span limits, tags and references. |
| **Process tree** | Reconstructed tree with per-process detail, top APIs and category mix. |
| **Behaviour graph** | Markov transition graph drawn with `QPainter` — nodes sized by call volume, arrow thickness by transition count, click a node to filter the transition table. |
| **Heatmap** | Processes × categories heatmap; click a cell to list the matching calls. Plus an API frequency table with the suspicion note per API. |
| **Indicators** | Indicators with type filter and confidence floor, a defanged list for tickets, copy-all and CSV export. |
| **Report & Export** | Preview and export the full report in every format. |

---

## Analysis options

`Tools ▸ Analysis settings…` (persisted to `data/settings.json`):

| Setting | Default | Meaning |
|---|---|---|
| Maximum parsed calls | 2 000 000 | hard cap while parsing |
| Mining sample size | 120 000 | evenly spaced sample used for n-gram/Markov mining |
| Loop collapse threshold | 3 | runs longer than this are reported as a collapsed loop |
| Minimum n-gram occurrences | 2 | ignore one-off tuples |
| Cluster minimum support | 2 | minimum repetitions for a mined cluster |
| Minimum pattern severity | low | drop lower-severity findings |
| Minimum IOC confidence | 0.00 | confidence floor for indicators |
| Burst threshold | 40 | calls/second that count as a burst |
| Ignored categories | – | e.g. `system, sync` to reduce noise |
| Timeline buckets | 120 | resolution of the timeline chart |

---

## Demo fixtures

All four are generated in memory and analysed through the real pipeline:

| Fixture | Format | Behaviour | Result |
|---|---|---|---|
| `cape-injection` | CAPE JSON | process injection, run-key persistence, dropped DLL, HTTPS beacon | 3 processes, 9 findings (critical), 16 indicators |
| `cuckoo-ransomware` | Cuckoo JSON | vssadmin shadow deletion, encryption loop, service install, README drop | 3 processes, 8 findings (critical), 22 indicators |
| `jsonl-stealer` | JSON Lines | browser credential staging, lsass read, PowerShell, upload | 1 process, 3 findings (high), 15 indicators |
| `cape-bson` | CAPE BSON | self-modifying memory, process hollowing, schtasks, relay beacon | 2 processes, 3 findings (high), 10 indicators |

---

## Layout

```
run.py                  launcher (GUI or headless CLI)
build_exe.py            PyInstaller portable build
app/
  config.py             app metadata, portable data paths, settings store
  main.py               CLI + GUI entry point
  demo.py               offline fixtures (CAPE/Cuckoo JSON, JSONL, BSON)
  reporting.py          Report model + HTML/PDF/JSON/CSV/MD exporters
  bus.py                log bus shared by every view
  core/
    ingest.py           format detection, parsing, normalisation, loop collapse
    categorize.py       API categories + suspicion notes
    model.py            ApiCall / ProcessNode / PatternMatch / n-gram models
    sequences.py        n-grams, maximal clusters, Markov transitions, bursts
    detection.py        behavioural pattern catalogue + matcher + scoring
    iocs.py             indicator extraction
    bsonx.py            BSON codec for CAPE logs (encode + decode)
    fastjson.py         orjson-backed JSON helpers
    store.py            SQLite case store
    engine.py           the pipeline and the report builder
  ui/
    shell.py            shared app shell (tabs, console, menus, report tab)
    report_panel.py     preview + export/download
    views.py            the nine workbench views
    graphs.py           behaviour graph + heatmap (QPainter)
    widgets.py          shared widget kit (tables, charts, stat strip, …)
    theme.py            dark analyst theme
```

## Documentation

* `architecture.md` — the design of record.
* `state.md` — implementation status and verification evidence.
* `memory.md` — durable notes for whoever works on this next.

## Dependencies

PySide6 (GUI + PDF export) and, optionally, `orjson` for faster JSON parsing.
The BSON reader, the mining, the pattern engine, the charts and the exporters are
all implemented in this repository — no plotting, YARA or pefile dependency.
