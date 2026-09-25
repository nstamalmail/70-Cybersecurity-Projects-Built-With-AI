# CPS - Custom Proxy Server (HTTP CONNECT + SOCKS5): State

## Status: COMPLETE (tunnels verified on loopback, reports + import working)

## What this is
Asyncio proxy per `architecture.md`: HTTP CONNECT and SOCKS5 on a single port with
auto protocol detection, optional basic auth, domain blocklist enforcement, a live
traffic log with byte counters, and reports in TXT/JSON/CSV/HTML/PDF.

## Components
- `src/cps/engine.py`     - asyncio proxy server: first-byte sniffing (HTTP vs SOCKS5),
  CONNECT header drain, SOCKS5 greeting/auth/CONNECT, blocklist filter, traffic
  recording, graceful shutdown.
- `src/cps/reporting.py`  - traffic report dict -> TXT/JSON/CSV/HTML/PDF.
- `src/cps/theme.py`      - dark QSS theme.
- `src/cps/main.py`       - PySide6 GUI: server controls, blocklist editor, live traffic
  table with per-connection rows, File > Import Traffic Log (JSONL), File > Export Report.
- `sample_data/`          - `traffic_corp_morning.jsonl` (18 importable records),
  `blocklist_sample.txt` (loadable blocklist).
- `tests/smoke_gui.py`    - CONNECT tunnel + SOCKS5 + blocklist + reports + GUI.

## How to run
```
cd "06. Custom proxy server (HTTPSOCKS5)"
python src/cps/main.py          # GUI
python tests/smoke_gui.py       # smoke test
```

## Verified
- HTTP CONNECT through the proxy reaches a local HTTP target (headers drained before
  tunneling so the target sees a clean request).
- SOCKS5 no-auth CONNECT on the same port (auto-detect) works.
- Blocklisted domains are refused with a clear reason and logged.
- 5 report formats written; JSONL import (18 records) renders the table and exports.
- GUI boots offscreen; traffic rows populate; CancelledError noise silenced on stop.

## Notes
- Single port hosts both protocols: first byte `0x05` => SOCKS5, anything else => HTTP.
- The proxy is loopback/test friendly: no upstream chaining, no TLS interception
  (CONNECT tunnels bytes opaquely).
