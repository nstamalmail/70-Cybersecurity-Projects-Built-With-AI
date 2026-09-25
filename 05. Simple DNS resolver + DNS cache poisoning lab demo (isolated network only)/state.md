# DRCP - DNS Resolver + Cache Poisoning Lab: State

## Status: COMPLETE (both lab scenarios verified end-to-end)

## What this is
Isolated-network DNS lab per `architecture.md`: a real UDP resolver (dnslib), a fake
authoritative upstream, a Kaminsky-style attack engine, cache inspector, and defense
demonstrations (source-port randomization, DNSSEC-mode validation). Reports in 5 formats.

## Components
- `src/drcp/engine.py`     - Resolver (threaded UDP, txn-id + source-port validation,
  LRU cache, race_hold modeling), FakeAuthoritative (signed responses), AttackEngine
  (sequential/known/random txn-id guessing), Lab orchestrator + scenarios.
- `src/drcp/reporting.py`  - lab report dict -> TXT/JSON/CSV/HTML/PDF exporters.
- `src/drcp/theme.py`      - dark QSS theme.
- `src/drcp/main.py`       - PySide6 GUI: resolver tab, attack lab tab, cache inspector,
  timeline log, File > Import Lab Session (JSON), File > Export Report.
- `sample_data/`           - `poisoning_success_session.json` (attack wins),
  `defended_session.json` (defenses hold).
- `tests/smoke_gui.py`     - both scenarios + reports + GUI smoke (offscreen Qt).

## How to run
```
cd "05. Simple DNS resolver + DNS cache poisoning lab demo (isolated network only)"
python src/drcp/main.py          # GUI
python tests/smoke_gui.py        # smoke test (runs both lab scenarios)
```

## Verified
- Scenario "poisoning": without defenses the attacker poisons the cache (forged IP
  cached, verdict snapshotted before legit refresh can self-heal it).
- Scenario "defended": with port randomization / DNSSEC-mode validation every forged
  response is rejected; attack reports success=False.
- 5 report formats written; PDF magic verified; imports render timeline + cache.

## Notes
- Loopback-only by design (127.0.0.1 resolver on port 5311, upstream on 5401);
  nothing contacts real DNS servers. Labeled "isolated network only" in the UI.
- Windows SIO_UDP_CONNRESET ioctl is set on UDP sockets to suppress the spurious
  ConnectionResetError storms when a client socket closes without reading.
