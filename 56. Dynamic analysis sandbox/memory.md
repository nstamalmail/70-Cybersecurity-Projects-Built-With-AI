# memory.md — Dynamic Analysis Sandbox (DAS)

Durable context for anyone (human or agent) picking this workbench up later.
Everything here was learned while implementing `architecture.md`; read it before
changing the code.

## 1. Identity

| Field | Value |
|---|---|
| Directory | `56. Dynamic analysis sandbox/` |
| Package | `app/` (entry: `run.py` -> `app.main:main`) |
| Slug / acronym | `das` / DAS |
| Exe name | `DAS-DynamicAnalysisSandbox.exe` |
| Architecture spec | `architecture.md` (design of record) |

## 2. Architecture in one screen

```
run.py / exe
  └── app/main.py             GUI or headless CLI (--analyze/--demo/--selftest)
        ├── app/ui/shell.py      AppShell: header chips, tabs, console dock, menus, Report tab
        │     └── ui/main_window.py  MainWindow: 8 views + ReportPanel + SettingsDialog
        │           └── ui/views.py  SessionView, TimelineView, ProcessesView,
        │                            NetworkView, ArtifactsView, ApiCallsView,
        │                            IOCView, BackendsView
        └── app/core/engine.py  Engine (stages: intake→hash→isolation→detonate→ingest
              │                        →augment→iocs→report)
              ├── core/model.py       Session, BehaviorEvent, ProcessNode
              ├── core/ingest.py      JSON / JSONL / Cuckoo-CAPE / Sysmon ingestion
              ├── core/hypervisor.py  VirtualBox / KVM / Simulated adapters + catalogue
              ├── core/iocs.py        IOC extraction & defanging
              └── core/hashing.py     MD5 / SHA-1 / SHA-256 / entropy
```

The run happens on a `QThread` (`SandboxWorker`) which imports `app.demo` for the
demo scenarios; the engine keeps a reference to a collector callback so the same
lifecycle serves live telemetry, imported captures and the simulation harness.

## 3. Contracts that must not break

1. **`Engine` API** — `analyze(path, progress=…)`, `detonate(path, progress=…,
   dry_run=…, collect=…)` and `_log(message, level)`; both return a
   `DetonationResult` with `.session`, `.signatures`, `.iocs`, `.severity`,
   `.score`, `.report` and `.summary_rows()`.
2. **`Report`/`export_report`** — `app/reporting.py` is shared verbatim with the
   eight other workbenches. Formats: `html`, `pdf`, `json`, `csv`, `md`,
   `iocs.csv`. `main.py --selftest` depends on all six.
3. **`demo.DEMO_KINDS`** and `demo.run_demo(engine, kind, progress=…)`.
4. **Signals** — `SessionView.ingestRequested/detonateRequested/demoRequested`;
   each view exposes `set_result(result)`; the report panel exposes `refresh()`.

## 4. Non-obvious details

* `BehaviorEvent.to_dict()` is the wire format for JSONL ingestion; ingestion
  accepts both `ts` (seconds, float) and ISO timestamps and normalises to seconds
  from run start. Do not change that contract without updating `ingest.py`.
* `Session.simulation` gates the "SIMULATED" banners in the UI, console and report.
  Any new synthetic path must set it (and add to `warnings`) or the report will
  misrepresent the data.
* Demo telemetry is written as plain JSON into `data/demo/`; the sample artefact is
  `demo_sample_placeholder.txt.SAMPLE` and is intentionally not executable.
  Windows Defender will quarantine anything that looks like a real sample — keep
  demo payloads inert.
* Hypervisor detection is by executable presence (`VBoxManage`, `virsh`) plus
  settings, so `adapter_catalogue()` is safe to call on a machine with neither.
* The engine refuses to fabricate telemetry for a real adapter (see `_collector` in
  `ui/main_window.py`); preserve that behaviour when adding adapters.

## 5. Where to extend

| Want to… | Touch |
|---|---|
| Add a behavioural signature | `core/engine.py` `SIGNATURES` |
| Add a telemetry source | `core/ingest.py` (register a reader) |
| Add a hypervisor | `core/hypervisor.py` (adapter + catalogue entry + `EXECUTABLES`) |
| Add an IOC type | `core/iocs.py` `_add` call sites |
| Add a report section | `core/engine.py` `_build_report` |
| Add an export format | `app/reporting.py` `exporters` |
| Change isolation policy | `core/engine.py` `_isolation_plan` + settings dialog defaults |

## 6. Reproduce everything

```bash
pip install -r requirements.txt
python run.py --selftest --out ./tmp-reports          # pipeline + all exports
python build_exe.py --clean                           # portable exe
dist/DAS-DynamicAnalysisSandbox.exe --selftest        # frozen verification
```
