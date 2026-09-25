# Dynamic Analysis Sandbox (DAS)

GUI workbench for **isolated, reproducible dynamic analysis** of suspicious Windows
samples: it reverts a VM to a clean snapshot, detonates the sample inside the guest,
ingests the behaviour telemetry and turns it into a navigable timeline, process tree,
network view, file/registry delta and IOC list — then exports a report you can hand
to someone else.

Implements `architecture.md` in this folder (§3–§6, §8, §12): the orchestration
lifecycle, the normalised `BehaviorEvent` model, the streaming telemetry ingestion,
the hypervisor abstraction and the reporting layer.

> **Scope.** This is a defensive analysis tool. Samples are treated as inert data:
> they are hashed, submitted to an isolated guest, and observed. Nothing here
> executes code on the host, and the workbench ships an explicit simulation harness
> so the whole workflow can be demonstrated without a hypervisor or a live sample.

---

## What it does

| Stage | Detail |
|---|---|
| **Intake** | Hash (MD5 / SHA-1 / SHA-256), size, type sniff; the sample is never executed on the host |
| **Isolation** | VM reverted to `clean-baseline`, headless boot, hypervisor-level networking (`--nic1 null`, no NAT/bridged), no shared folders or clipboard |
| **Detonation** | Guest agent uploads the sample, executes it with the right package (exe/dll/doc/url), streams telemetry back while the sample runs |
| **Ingestion** | Accepts real guest telemetry (JSON Lines / JSON session dumps) *or* the simulation harness |
| **Analysis** | 14 behavioural signatures, severity scoring, event-type counters, IOC extraction |
| **Report** | HTML / PDF / JSON / CSV / Markdown / IOC-CSV with an export + download panel |

### Views

`Session & Detonation` · `Timeline` · `Process Tree` · `Network` ·
`Files & Registry` · `API Calls` · `IOCs` · `Sandbox Back Ends` · `Report & Export`

---

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python run.py                       # GUI
python run.py --selftest            # headless: run every demo, export all report formats
python run.py --demo detonation     # headless: full detonation workflow (simulated harness)
python run.py --analyze capture.jsonl
python run.py --analyze capture.jsonl --formats html,pdf,iocs.csv --out ./reports
```

Accepted telemetry: DAS session JSON, Cuckoo/CAPE-style report JSON, JSON Lines
behaviour dumps, Sysmon-style event arrays.

## Build the portable executable

```bash
python build_exe.py --clean         # -> dist/DAS-DynamicAnalysisSandbox.exe  (one file, windowed)
python build_exe.py --onedir        # folder build, faster cold start
```

The exe is self-contained (no Python install) and stores cases, reports, logs and
settings in `data/` next to the executable, falling back to
`%LOCALAPPDATA%\das` when that folder is read-only.

```bash
dist/DAS-DynamicAnalysisSandbox.exe --selftest --out ./selftest-reports
```

---

## Report generation and export

Every run produces a report object that the **Report & Export** tab renders as
sections. From there you can:

* browse the sections in the UI,
* **export** to HTML, PDF, JSON, CSV (events), Markdown or a dedicated IOC CSV,
* **download** the file (the panel writes it to the reports folder and reveals it),
* re-export the last report after tweaking the options.

Headless runs export the same formats through `--formats`.

---

## Reports, cases and settings

```
data/
├── cases/           ingested sessions: manifest, events, processes, signatures, IOCs
├── demo/            synthetic demo telemetry written by the demos (clearly labelled)
├── reports/         exported reports
├── logs/session.log  session log
└── settings.json     persisted settings
```

## Isolation notes

* Snapshot revert before *every* run; VMs are never reused after a detonation.
* Networking is severed at the hypervisor level; the optional simulation mode
  answers DNS/HTTP with canned data so network behaviour is triggered without egress.
* Samples stay defanged (`.SAMPLE` / password-protected archive) and are hashed
  before and after transfer.
* Hypervisor commands default to **dry-run**; the UI asks for confirmation before
  any real command is issued.

## Layout

```
app/
├── config.py        metadata + portable paths + settings store
├── bus.py           structured log bus (also mirrored into the session log)
├── reporting.py     report model, exporters (HTML/PDF/JSON/CSV/MD), templates
├── demo.py          synthetic telemetry (never executable) + demo scenarios
├── core/
│   ├── model.py     Session, BehaviorEvent, ProcessNode
│   ├── ingest.py    JSON / JSONL / Cuckoo-CAPE / Sysmon-style ingestion
│   ├── hypervisor.py hypervisor adapters (VirtualBox, KVM, simulated)
│   ├── iocs.py      IOC extraction from behaviour + network
│   └── engine.py    orchestrator: detonation lifecycle, signatures, scoring
└── ui/              theme, widgets, report panel, shell, views, main window
```

## Status

See `state.md` for build/verification status and `memory.md` for the design
decisions taken while implementing the architecture.
