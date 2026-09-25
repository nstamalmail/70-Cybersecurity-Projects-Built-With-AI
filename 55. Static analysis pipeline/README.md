# Static Analysis Pipeline (SAP)

A GUI-driven, **read-only** first-pass triage workbench for suspicious Windows
executables, built to the specification in [`architecture.md`](architecture.md).

![stack](https://img.shields.io/badge/python-3.10%2B-blue) ![gui](https://img.shields.io/badge/GUI-PySide6%20%2F%20Qt6-41cd52)

## What it does

| Capability | Detail |
|---|---|
| **Hashing** | MD5, SHA-1, SHA-256 in a single streaming pass, plus `imphash` |
| **PE parsing** | Machine, timestamp, entry point/section, image base, subsystem, DLL characteristics, section table with **Shannon entropy**, imports, exports, resources, debug/PDB, Rich header, overlay |
| **Anomaly detection** | High-entropy sections, W+X sections, entry point outside `.text` / in the last section, packer section names, timestomping, minimal imports, missing DEP, large overlay, DLL with no exports |
| **Capability mapping** | 60+ abused Windows APIs grouped into process-injection, persistence, network, crypto, execution, evasion, anti-analysis and discovery |
| **Strings** | ASCII + UTF-16LE extraction with 19-pattern classification (URL, IP, domain, registry, file path, command, credential, mutex, user-agent, PDB, TOR, BTC, base64, API, GUID, hashes) and keyword themes (ransomware, credential theft, persistence, evasion, C2, lateral movement) |
| **Threat intel** | Hash-only lookups against VirusTotal v3, MalwareBazaar and AlienVault OTX with rate limiting, on-disk caching and graceful degradation. **The sample is never uploaded.** |
| **Verdict** | Weighted scoring with a full rationale table, thresholds ≥60 MALICIOUS / 25-59 SUSPICIOUS / <25 LIKELY CLEAN, plus an audit-logged analyst override |
| **IOCs** | Consolidated, deduplicated, confidence-scored indicator list with private-range and vendor-noise filtering and one-click **defanging** for safe sharing |
| **Reports** | HTML, **PDF**, JSON, CSV, Markdown and a defanged IOC CSV - preview, export to any location, or dump every format at once |

**Safety posture:** the sample is only ever read as bytes. It is never executed,
never uploaded, never modified and never copied. Windows executables are parsed
with `pefile` in-process; network use is opt-in.

## Install & run

```bash
pip install -r requirements.txt
python run.py                     # GUI
```

Portable single-file executable (no Python needed on the target machine):

```bash
python build_exe.py               # -> dist/SAP-StaticAnalysisPipeline.exe  (~49 MB)
```

## Headless / automation

```bash
python run.py --analyze C:/samples/suspicious.exe --out ./reports
python run.py --demo packed --formats html,pdf,json
python run.py --selftest          # runs every demo scenario and exports all formats
```

The built exe accepts the same switches:

```
SAP-StaticAnalysisPipeline.exe --selftest --out ./reports
```

## Using the GUI

1. **Sample & Pipeline** - drop a file (or press *Load demo data*) and pick your
   options, then *Run analysis*. Stage-by-stage progress is shown live.
2. **Hashes** - MD5/SHA-1/SHA-256/imphash with copy and a *Look up hashes* button.
3. **PE Inspector** - header grid plus tabs for sections (with an entropy chart),
   imports, exports, resources, debug/PDB and anomalies.
4. **Strings** - filtering table of every extracted string, classification chart
   and keyword themes.
5. **Capabilities** - suspicious imports grouped by the capability they enable.
6. **Verdict** - colour-coded verdict, contributing indicators with weights, the
   threat-intel matrix and the override control.
7. **IOCs** - indicator table, type histogram, defang toggle and CSV export.
8. **Report & Export** - preview the generated report and export it
   (HTML / PDF / JSON / CSV / Markdown / all formats), open the reports folder or
   open the last export.

## Demo data

`Load demo data` offers three scenarios so every view is reachable without any
real malware:

| Scenario | What it exercises |
|---|---|
| **Synthetic packed sample** | A hand-built PE image with packer traits (high-entropy W+X section, entry point in the stub, injection/network imports, C2 strings, PDB path, overlay) → **MALICIOUS**. Built **in memory only** - see the safety note below. |
| **Benign updater sample** | An ordinary release-style build → **LIKELY CLEAN** |
| **Inert text script** | The strings-only path for non-PE input → **SUSPICIOUS** |

> **Safety note.** The synthetic "packed" sample is inert header data - it has no
> executable code - but endpoint protection legitimately quarantines on-disk
> files that look like this. It is therefore generated **in memory** and analysed
> through the buffer path, so nothing suspicious is ever written to disk. Only the
> benign sample and the text sample are written to the demo folder, and every
> demo finding is labelled `SYNTHETIC` in the console and the report.

Bring your own samples with *Browse* / drag-and-drop, or `--analyze`.

## Where data goes

Portable-first: `data/` next to the exe (or this folder when run from source):
`reports/`, `cases/<run-id>/` (hashes, PE info, anomalies, capabilities, strings,
IOCs, verdict, manifest), `cache/intel/`, `logs/session.log`, `settings.json`.
If that folder is read-only the app falls back to `%LOCALAPPDATA%/sap`.

## Layout

```
app/
  main.py            GUI + headless CLI entry point
  config.py          metadata, portable paths, settings store
  bus.py             log bus (Qt signals + session.log)
  reporting.py       report model and HTML/PDF/JSON/CSV/Markdown exporters
  demo.py            synthetic demo scenarios
  core/              hashing, PE parsing, strings, intel, verdict, IOCs, pipeline
  ui/                shell, theme, widgets, report panel, views, main window
build_exe.py         PyInstaller portable build
run.py               source launcher
```

## Known limitations

* String extraction is regex based; it does not decode encrypted/obfuscated
  strings (a FLOSS-style decoder is a documented future extension).
* Packer identification is section-name based rather than DIE/PEiD signatures.
* `.NET` and Office documents are hashed and string-scanned but not parsed
  structurally.
* Signer verification is reported as unknown unless a signature blob is present.
* Threat intel requires your own API keys and explicit opt-in.

## Legal / ethical use

This tool performs defensive static analysis only. Use it on samples you are
authorised to handle, prefer public defensive repositories (MalwareBazaar,
theZoo) or purpose-built test files, and keep any real sample inside an isolated
lab machine.
