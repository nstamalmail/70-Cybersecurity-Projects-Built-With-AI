# memory.md — Static Analysis Pipeline (SAP)

Durable context for anyone (human or agent) picking this workbench up later.
Everything here was learned the hard way during implementation; read it before
changing the code.

## 1. Identity

| Field | Value |
|---|---|
| Directory | `55. Static analysis pipeline/` |
| Package | `app/` (entry: `run.py` -> `app.main:main`) |
| Slug / acronym | `sap` / SAP |
| Exe name | `SAP-StaticAnalysisPipeline.exe` |
| Architecture spec | `architecture.md` (design of record) |

## 2. Architecture in one screen

```
run.py / exe
  └── app/main.py            GUI or headless CLI (--analyze/--demo/--selftest)
        ├── app/ui/shell.py      AppShell: header, tabs, console dock, menus, Report tab
        │     └── ui/main_window.py  MainWindow: 7 views + ReportPanel
        │           └── ui/views.py  SampleView, HashView, PEView, StringsView,
        │                            CapabilitiesView, VerdictView, IOCView
        └── app/core/engine.py   AnalysisEngine  (stages: load→hash→pe→strings→intel→iocs→verdict→report)
              ├── core/hashing.py     MD5/SHA-1/SHA-256, entropy, magic types
              ├── core/peanalysis.py  pefile parsing + capability + anomaly derivation
              ├── core/stringsx.py    ASCII/UTF-16 extraction + classification + keyword themes
              ├── core/intel.py       VT/MalwareBazaar/OTX hash lookups + cache
              ├── core/verdict.py     weighted scoring + rationale + override
              ├── core/ioc.py         IOC compilation/dedup/defanging
              └── core/pebuilder.py   inert synthetic PE generator (demo only)
```

The pipeline runs on a `QThread` (`AnalyzeWorker`) and streams stage updates via
Qt signals; the engine itself never imports Qt except in `_write_artifacts`-free
code paths, so it is fully testable headlessly.

## 3. Contract that must not break

The shared front-end layer (identical in all ten workbenches) depends on:

* `app.config.APP` - dict with `slug, name, acronym, version, subtitle, report_title, artifact_noun, accent, file_filters, description, settings`.
* `app.config.SETTINGS` - JSON-backed settings store (`get/set/update/save`).
* `app.config.data_root()/reports_dir()/logs_dir()/cases_dir()/cache_dir()/demo_dir()/exports_dir()/settings_path()`.
* `app.demo.run_demo(engine, kind, progress=None)` and `app.demo.DEMO_KINDS`.
* `app.core.engine.Engine(settings, bus)` with `.analyze(path, progress=..., write_artifacts=...)`.
* `result.report` -> `app.reporting.Report`, `result.summary_rows()` -> `list[(label, value)]`.
* `app.reporting.export_report(report, path, fmt)` / `export_all(report, dir)` with formats `html|pdf|json|csv|iocs.csv|md`.

If you change any of those, change them in **all** workbenches (the files are
copies, there is no shared package).

## 4. Hard-won lessons

1. **Never write a packer-like PE to disk.** Defender quarantines it and the file
   becomes unreadable (`OSError: [Errno 22] Invalid argument`) even though
   `exists()` still returns `True`. Verified: `packed` variant blocked, `clean`
   variant fine. Demo payloads of this kind stay in memory.
2. **Never hand `pefile` a path you did not normalise.** `pefile.PE(path)` opens
   the file itself and fails on paths containing non-UTF-8 bytes (cp1252 `–` in
   this very repository path). Use `pefile.PE(data=bytes)`.
3. **Sample reads need retries.** A freshly written `.exe` can be locked by the
   AV scanner for a second or two; `engine._read_bytes` retries 4x with backoff
   and produces a human-readable error.
4. **Vendor noise must be filtered in two places.** `ioc._NOISE` excludes
   `microsoft.com`, scheme URIs, system DLLs etc. from the IOC list; the verdict
   engine calls `ioc.is_noise()` for the same reason. Forgetting the second one
   leaves a benign demo at SUSPICIOUS.
5. **Registry strings are not persistence by themselves.** Only paths matching
   `verdict.PERSISTENCE_KEY_RE` (Run/RunOnce/Services/Winlogon/IFEO/…) score.
6. **PE header maths.** For PE32 the optional header is 0xE0 bytes: fields end at
   0x178, where the section table starts; `SizeOfHeaders` must cover it (0x400
   with FileAlignment 0x200). Writing the section table at the wrong offset
   silently breaks sections, imports and DllCharacteristics at once.
7. **CodeView PDB records need the `RSDS` magic**, otherwise `pefile` does not
   populate `PdbEntry.PdbFileName` and the PDB path is lost.
8. **Windowed PyInstaller builds have `sys.stdout is None`.** `main._ensure_streams`
   attaches to the parent console (`AttachConsole`) or falls back to
   `data/logs/cli.log`.
9. **cp1252 consoles crash on `→`/`✓`.** Reconfigure stdout to UTF-8 with
   `errors="replace"` (done in `_ensure_streams`).
10. **`report.iocs` must be assigned**, not only rendered via `add_ioc_section()`,
    or the IOC-only CSV export comes out empty.

## 5. Weight table (verdict)

| Indicator | Weight |
|---|---|
| Intel ratio > 10 engines | +40 |
| Intel ratio 1-10 engines | +20 |
| Known family from intel | +30 |
| Intel queried, zero detections | −30 |
| Section entropy > 7.0 (per section) | +15 |
| Suspicious imports, worst weight ≥ 10 | +15, else +8 |
| W+X section | +10 |
| Entry point outside `.text` | +10 |
| Network indicators in strings | +10 |
| Command strings | +8 |
| Ransomware / credential-theft keyword themes | +12 |
| C2 / evasion / lateral keyword themes | +8 |
| Persistence registry paths / packer hint / overlay / minimal imports / future timestamp | +5 |
| Not signed | +5 |
| Signed by trusted publisher | −20 |

Score is clamped to 0-100; `≥60` MALICIOUS, `25-59` SUSPICIOUS, `<25` LIKELY CLEAN.

## 6. Environment

* Python 3.12.7, PySide6 6.11.2, pefile (installed), PyInstaller 6.22.2, requests.
* Build: `python build_exe.py --clean` → one-file windowed exe, ~49 MB. The
  excludes list drops QtWebEngine/Qml/Charts/Multimedia/etc.
* Test: `python run.py --selftest` must print `RESULT: PASS`.
* GUI smoke test (headless): `QT_QPA_PLATFORM=offscreen python -c "from app.ui.main_window import MainWindow; ..."`.

## 7. Deliberate non-goals

No sample upload, no execution, no offensive tooling, no silent network calls.
Threat intel is opt-in, hash-only and clearly reports `disabled` when offline.
