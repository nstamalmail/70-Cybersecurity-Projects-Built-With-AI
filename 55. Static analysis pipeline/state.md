# state.md — Static Analysis Pipeline (SAP)

**Status:** ✅ Complete — implemented, verified end-to-end, portable exe built
**Version:** 1.0.0
**Last updated:** 2026-09-17

## Component status

| Area | State | Notes |
|---|---|---|
| Portable runtime paths | ✅ | `data/` next to the exe, `%LOCALAPPDATA%/sap` fallback, `settings.json` store |
| Hash engine | ✅ | MD5/SHA-1/SHA-256 single pass, streaming, `imphash`, Shannon entropy, magic-byte type detection |
| PE parser | ✅ | `pefile` based; headers, 4-section demo parses cleanly, imports/exports/resources/debug/Rich header/overlay |
| Anomaly engine | ✅ | 12 checks, severities low/medium/high |
| Capability mapper | ✅ | 60+ abused APIs across 9 capability groups |
| String extractor | ✅ | ASCII + UTF-16LE, 19 classification patterns, 6 keyword themes |
| Threat intel | ✅ | VT v3 / MalwareBazaar / OTX hash-only clients, cache, throttling, offline + simulated modes |
| Verdict engine | ✅ | Weighted rationale, thresholds 60/25, analyst override with audit fields |
| IOC compiler | ✅ | Dedupe, merge sources, confidence, private-range + vendor-noise filtering, port normalisation, defanging |
| Reporting | ✅ | HTML, PDF (Qt), JSON, CSV, IOC-only CSV, Markdown; per-format and all-formats export |
| GUI | ✅ | 8 tabs, worker-threaded pipeline, live stage progress, override workflow, settings dialog |
| CLI | ✅ | `--analyze`, `--demo`, `--selftest`, `--out`, `--formats`, console reattach for windowed exe |
| Portable exe | ✅ | `dist/SAP-StaticAnalysisPipeline.exe`, 48.6 MB one-file, GUI launches, `--selftest` PASS |
| Docs | ✅ | README.md, state.md, memory.md |

## Verification evidence

```
$ python run.py --selftest --quiet --out ./tmp-reports
demo:packed   -> MALICIOUS   (score 100, raw 130) | 4 sections | 94 strings | 9 anomalies | 19 IOCs | 16 report sections
demo:benign   -> LIKELY CLEAN(score  10, raw  10) | 4 sections | 27 strings | 1 anomaly  |  9 IOCs | 10 report sections
demo:script   -> SUSPICIOUS  (score  50, raw  50) | strings-only path            | 10 IOCs |  9 report sections
RESULT: PASS      # 6 export formats each, including a valid PDF

$ dist/SAP-StaticAnalysisPipeline.exe --selftest --out ./selftest-reports
RESULT: PASS      # identical results from the frozen exe
```

GUI end-to-end (offscreen Qt harness): window builds with 8 tabs, worker runs the
pipeline off the UI thread, all views populate, the report panel renders 21
tabs, `export_all` writes 5 files, and switching scenarios updates the header
chips and verdict banner.

## Design decisions made during implementation

1. **In-memory demo payloads.** Windows Defender quarantines on write any file
   containing the synthetic packer-looking PE (measured: read fails with
   `OSError 22` for the packed variant, succeeds for the benign variant). The
   packed demo is therefore generated and analysed purely in memory.
2. **Path-independent PE parsing.** `pefile.PE(data=...)` is used instead of
   `pefile.PE(path)` because forensic/archive paths can contain bytes that are
   not valid UTF-8 (this repository's own path includes a cp1252 en dash).
3. **Defensive file reading.** Reads retry 4 times with backoff and emit an
   explanatory error, because AV/EDR scanners routinely hold a transient lock on
   freshly written samples.
4. **Vendor noise filter shared by IOCs and the verdict**, so a benign
   `microsoft.com` URL neither becomes an IOC nor raises the score (this moved
   the benign demo from SUSPICIOUS 26 to LIKELY CLEAN 10).
5. **Generic front end.** `main.py`, the shell, widgets, report panel and
   reporting layer are app-agnostic (they read `APP` from `config.py`), so all ten
   workbenches share one implementation.
6. **`interactive` flag on the report panel** so automated tests can export
   without a modal dialog blocking them.

## Open items / future work

* FLOSS-style string deobfuscation module (architecture §13.4).
* DIE/PEiD signature-based packer detection (currently section-name heuristics).
* OS keychain storage for API keys (currently a local JSON settings file).
* Batch/multi-file queue (architecture §13.6) and YARA scanning module.
* Authenticode signer verification.
