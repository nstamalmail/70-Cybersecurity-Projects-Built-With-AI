# state.md — Live Project State

> Purpose: snapshot of **current** progress. Updated after every meaningful step.
> For durable, long-lived knowledge see `memory.md`. For design see `architecture.md`.

## Snapshot

- **Project:** C2 Detection Workbench — synthetic, offline, detection-focused
- **Phase:** ✅ **COMPLETE & VERIFIED** (v1.0.0)
- **Python:** 3.12.7 · PyInstaller 6.22.2 · Windows (Git Bash)
- **Last updated:** 2026-09-09 (build session)

## Completed
- [x] `architecture.md` — full spec (S1–S6 safety constraints, D1–D9 rule table)
- [x] `memory.md` + `state.md` — durable knowledge + live state
- [x] Simulator engine: `flows.py`, `encoders.py`, `pcap.py`, `scenario.py`, `traffic.py`
- [x] Detection engine: `src/detections.py` (D1–D9, pure functions, scored verdicts)
- [x] Zero-trust module: `src/ztn.py` (allow/verify/deny + audit JSON)
- [x] Pipeline: `src/pipeline.py` (pcap + conn.log + eve.json + flows.csv + ztn audit)
- [x] Safety guard: `src/safety.py` (static AST scan, wired into every run)
- [x] GUI: `src/gui/` (8 tabs, worker thread + queue, chunked inserts, canvas pie/timeline)
- [x] Entrypoint: `app.py` (GUI / `--smoke` / `--self-test` / `--version`)
- [x] Tests: `tests/` — **40 passed** (safety, encoders, pcap structure, D-rules, e2e, determinism)
- [x] GUI smoke: `scripts/gui_smoke.py` — **PASSED** (8 tabs, run + filter exercised)
- [x] Portable exe: `dist/C2DetectionWorkbench.exe` (10.4 MB) — **`--smoke` exit 0**, no missing modules in warn file

## Verified Behavior (seed 1337)
| Scenario | Flows | Malicious | Suspicious | Rules fired |
|---|---|---|---|---|
| c2_domain_fronting | 1305 | 90 | 0 | D1 D2 D3 D6 D7 D8 D9 |
| c2_dga | 1349 | 90 | 44 | D1 D2 D3 D5 D6 D7 D8 D9 |
| ransomware_checkin | 1312 | 120 | 0 | D2 D3 D4 D6 D8 D9 |
| benign_only (control) | 1206 | 0 | 0 | D9 only |

## Key Decisions
| Decision | Rationale |
|----------|-----------|
| tkinter over PySide6 | Ships with python.org Windows builds → dep-free portable exe |
| Hand-rolled PCAP writer (struct.pack) | Byte-exact frames, no scapy dependency |
| Deterministic seeded PRNG everywhere | Same scenario+seed ⇒ byte-identical PCAP (tested) |
| D2 groups by (src, fingerprint) not (src, dst) | Edge rotation must not hide beacon rhythm |
| Findings carry evidence + explanation strings | The GUI "why" pane is the teaching payload |
| FlowRecord extracted to `flows.py` | Avoids import cycle traffic↔pcap |
| Role-based cohorts (browser/implant/ransom JA3+TTL) | Keeps negative control quiet; D3/D6/D8 scoped |

## Artifact Paths
- Per-run outputs → `artifacts/` (pcap, conn_*.log, eve_*.json, flows_*.csv, ztn_*.json)
- Portable exe → `dist/C2DetectionWorkbench.exe`; build dir `build/` (gitignored)

## How to Reproduce Verification
```bash
python -m pytest tests/ -q          # 40 passed
python app.py --self-test           # SAFETY OK
python app.py --smoke               # SMOKE PASSED
python scripts/gui_smoke.py         # GUI SMOKE PASSED
pyinstaller --onefile --windowed --name C2DetectionWorkbench --clean -y app.py
./dist/C2DetectionWorkbench.exe --smoke   # exit 0
```

## Environment Notes
- Windows + Git Bash: POSIX syntax only; paths with forward slashes.
- Console encoding mangled `—`/`…` in exe stdout (cp1252 console) — cosmetic only.
