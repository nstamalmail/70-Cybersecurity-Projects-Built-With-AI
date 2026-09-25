# WGTB - WireGuard Tunnel Builder: State

## Status: COMPLETE (keygen, config gen, QR, import, reports verified)

## What this is
WireGuard automation per `architecture.md`: Curve25519 keypair generation, server and
client wg-quick config generation, peer roster management, QR code export (PNG) for
client onboarding, topology import, and reports in TXT/JSON/CSV/HTML/PDF.

## Components
- `src/wgtb/engine.py`     - Keypair generation (cryptography X25519), preshared keys,
  config renderers (server/client [Interface]/[Peer] blocks), subnet planner for the
  tunnel network, TunnelSpec serialize/restore, QR PNG rendering via qrcode.
- `src/wgtb/reporting.py`  - tunnel report dict -> TXT/JSON/CSV/HTML/PDF.
- `src/wgtb/theme.py`      - dark QSS theme.
- `src/wgtb/main.py`       - PySide6 GUI: server form, peer table, per-peer config and
  QR preview (auto-selects row 0), File > Import Tunnel (JSON), File > Export Report,
  File > Export Client Config, File > Export QR (PNG).
- `sample_data/tunnel_branch_office.json` - importable 3-peer branch-office tunnel.
- `tests/smoke_gui.py`     - keygen + configs + QR + reports + import + GUI.

## How to run
```
cd "09. VPN tunnel builder (WireGuard automation script)"
python src/wgtb/main.py          # GUI
python tests/smoke_gui.py        # smoke test
```

## Verified
- Keypairs are real Curve25519 (cryptography lib); preshared keys generated per peer.
- Generated wg-quick configs parse structurally ([Interface]/[Peer] sections, keys in
  place) for the server and every client.
- QR PNG renders and decodes as PNG (magic bytes verified).
- 5 report formats written; sample tunnel imports and re-exports cleanly.
- GUI boots offscreen; peer row auto-selection makes the QR/config pane populate.

## Notes
- The tool generates configs only; it does not run wg or touch network interfaces.
- Private keys are shown once in the config view and flagged as sensitive in reports.
