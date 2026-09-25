# C2 Detection Workbench (Detection-Focused Demo)

Offline, synthetic-traffic training workbench that demonstrates **why domain-fronting-style
C2 obfuscation leaks detectable signals** — built for blue teams, students, and purple-team
facilitators. No packet ever leaves your machine.

## Quickstart

```bash
pip install -r requirements.txt
python app.py                 # GUI
python app.py --smoke         # headless pipeline verification (exit 0 = pass)
python app.py --self-test     # safety guard + encoder round-trips
python -m pytest tests/ -q    # full test suite
```

## Build the portable EXE (Windows)

```bash
pip install -r requirements.txt
pyinstaller --onefile --windowed --name C2DetectionWorkbench --clean -y app.py
# artifact: dist/C2DetectionWorkbench.exe   (no Python needed on the target machine)
```

Verify the exe headlessly: `dist/C2DetectionWorkbench.exe --smoke` (exit code 0 = pass).
SmartScreen may warn about unsigned exes — expected for demos.

## Safety contract (enforced in code, see `architecture.md` §0)

- No network I/O — a static AST guard (`src/safety.py`) hard-fails if any network-capable
  import ever enters the codebase (`tests/test_safety.py`).
- IPs restricted to RFC 5737 documentation ranges; domains to `.example`/`.invalid`.
- Didactic placeholder payloads only; the PCAP is a locally written file, not a capture.

## Detections (D1–D9)

D1 SNI/Host disjunction · D2 beacon periodicity · D3 TLS fingerprint clusters ·
D4 high-entropy bodies · D5 DGA hostnames · D6 rare-SNI pivoting · D7 URI anomalies ·
D8 TTL cohorts · D9 decoy discrimination (benign NTP negative control).

Artifacts per run land in `artifacts/`: `.pcap` (Wireshark-readable), Zeek-style
`conn.log`, Suricata-style `eve.json`, `flows.csv`, and a zero-trust audit JSON.

See `architecture.md` for the full design, `state.md` for live project state,
and `memory.md` for the durable knowledge base.
