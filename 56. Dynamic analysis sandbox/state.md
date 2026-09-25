# state.md — Dynamic Analysis Sandbox (DAS)

**Status:** ✅ Complete — implemented, verified end-to-end, portable exe built
**Version:** 1.0.0
**Last updated:** 2026-09-17

## Component status

| Area | State | Notes |
|---|---|---|
| Portable runtime paths | ✅ | `data/` next to the exe, `%LOCALAPPDATA%/das` fallback, `settings.json` store |
| Behaviour model | ✅ | `Session`, `BehaviorEvent`, `ProcessNode`; per-architecture fields (api_call, file, registry, network, process, service, task, shell, dropped_file) |
| Ingestion | ✅ | DAS native JSON, Cuckoo/CAPE-style report, JSON Lines, Sysmon-style arrays; tolerant of missing fields |
| Hypervisor abstraction | ✅ | `VirtualBoxAdapter`, `KVMAdapter`, `SimulatedAdapter`, `auto` selection; capability catalogue in the UI |
| Isolation controls | ✅ | Snapshot revert before every run, headless start, `--nic1 null` / no `-netdev`, no shared folders/clipboard, dry-run default |
| Detonation lifecycle | ✅ | revert → boot → agent upload → execute → stream collect → teardown → report, with staged progress |
| Behaviour signatures | ✅ | 14 signatures (persistence, VSS deletion, injection, LSASS access, DGA, beaconing, ransom mass-write, exfiltration, WMI subscription, self-delete…) |
| Severity scoring | ✅ | Weighted 0–100 score with rationale, mapped to critical/high/medium/low/info |
| IOC extraction | ✅ | IPs, domains, URLs, hashes, file paths, registry keys, mutexes, user-agents, service/task names, crypto wallets |
| Reporting | ✅ | HTML, PDF (Qt), JSON, CSV, IOC-only CSV, Markdown; export + reveal from the Report tab |
| GUI | ✅ | 9 tabs (8 views + Report & Export), worker-threaded runs, live stage progress, settings dialog |
| CLI | ✅ | `--analyze`, `--demo`, `--selftest`, `--out`, `--formats`, console reattach for windowed exe |
| Portable exe | ✅ | `dist/DAS-DynamicAnalysisSandbox.exe`, one-file windowed build; `--selftest` PASS |
| Docs | ✅ | README.md, state.md, memory.md |

## Verification evidence

```
$ python run.py --selftest --out ./tmp-reports
demo:detonation       -> CRITICAL (score 100) | 17 event types | 14 signatures | 124 IOCs | 30 report sections
demo:session-file     -> CRITICAL (score 100) | 14 signatures   | 124 IOCs | 30 report sections
demo:benign           -> INFO     (score   0) |  0 signatures   |  11 IOCs | 13 report sections
RESULT: PASS          # 6 export formats each, including a valid PDF
```

GUI end-to-end (offscreen Qt harness): window builds with 9 tabs, the worker runs
the detonation off the UI thread, every view populates, and the report panel
renders 32 sections for the ransomware scenario.

## Design decisions made during implementation

1. **Simulation harness, not fake hypervisor.** Real hypervisor adapters exist and
   issue real commands, but a run needs telemetry to be useful. When no guest-agent
   collector is configured the harness synthesises telemetry for the *simulated*
   adapter and every artefact is stamped `simulation: true`; on a real adapter the
   engine refuses rather than inventing data. "Never present synthetic data as a
   real detonation" is the invariant.
2. **Dry-run by default.** Hypervisor commands are composed and logged but not
   executed unless the analyst explicitly disables dry-run, and the UI asks for
   confirmation first. Nothing in the app can power on a VM by accident.
3. **Telemetry-first design.** The engine consumes a normalised event stream, so
   the same analysis pipeline serves a live guest agent, an imported Cuckoo/CAPE
   report and a hand-written JSONL capture. This is what makes the tool testable
   without a lab.
4. **No host execution, ever.** The "sample" path is only ever hashed and handed to
   the guest. Demo samples are inert text artefacts (`.SAMPLE`), never executables.
5. **Signatures in one table.** All 14 behavioural signatures live in a single
   declarative list in `core/engine.py` (id, severity, matcher, rationale) so
   adding detections does not touch the UI.
6. **Shared front end.** `main.py`, the shell, widgets, report panel and reporting
   layer are app-agnostic (they read `APP` from `config.py`), so all ten
   workbenches in this repository stay consistent.

## Known limitations

* Live VM orchestration needs a hypervisor plus the guest agent REST service; the
  adapters are implemented but were exercised against the dry-run/simulated paths
  (no hypervisor on the build host).
* PCAP parsing is represented by normalised network events; raw packet capture
  files are referenced, not decoded.
* Multi-VM parallel analysis is modelled (per-run worker + settings) but the UI
  runs one detonation at a time.
