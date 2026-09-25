# Project State — ARP Scanner

> Living document: update this file whenever the code changes materially.
> Companion files: `architecture.md` (design), `memory.md` (decisions & gotchas).

**Status: v1.0 — COMPLETE & VERIFIED** (all tests green, exe built and smoke-tested)

---

## 1. Component Inventory (what exists)

| Component | Path | State | Notes |
|---|---|---|---|
| Architecture doc | `architecture.md` | ✅ final | Detailed blueprint, goals G1–G6 + traceability §12 |
| Data model | `core/models.py` | ✅ done | `ScanConfig`/`Host`/`ScanResult`/`ScanEvent` frozen dataclasses |
| NIC discovery | `core/interface.py` | ✅ done + hw-verified | `GetAdaptersInfo` via ctypes; 656-byte struct size verified |
| Scan engine | `core/engine.py` | ✅ done + hw-verified | `SendARP` sweep, 128-thread pool, cooperative cancel |
| OUI database | `core/oui.py` | ✅ done | ~450 embedded prefixes; merges IEEE `oui.txt` if present |
| Exporters | `core/exporter.py` | ✅ done + verified | CSV (UTF-8 BOM) + JSON; dispatch by extension |
| GUI | `ui/app.py` | ✅ done + smoke-tested | Toolbar, sortable Treeview, statusbar, queue+after() drain |
| Entry point | `main.py` | ✅ done + verified | GUI default; `--cli CIDR [--csv] [--json]` headless mode |
| Unit tests | `tests/` | ✅ 26/26 pass | core logic + GUI smoke (dialog-safe, display-guarded) |
| Build script | `build.py` | ✅ done | venv bootstrap → PyInstaller → verify artifact |
| Portable exe | `dist/ARPScanner.exe` | ✅ built (10.9 MB) | onefile, windowed, no Python/Npcap/admin needed |

## 2. Verification Log (evidence, not claims)

| Check | Result | Date |
|---|---|---|
| `pytest tests/` | 26 passed | 2026-09-07 |
| `SendARP` self-probe (`192.168.0.101`) | MAC `4C:23:38:06:1C:51` returned | 2026-09-07 |
| `SendARP` gateway probe (`192.168.0.1`) | MAC `40:3F:8C:DF:50:68` returned | 2026-09-07 |
| `GetAdaptersInfo` on live system | RZ616 Wi-Fi 6E, `192.168.0.101/24`, gw found | 2026-09-07 |
| OUI lookup (`4C:23:38` → MediaTek, `40:3F:8C` → TP-Link) | correct | 2026-09-07 |
| CLI scan + JSON + CSV export | valid files, correct schema | 2026-09-07 |
| exe launch smoke test | GUI process alive after 9s, clean kill | 2026-09-07 |
| exe rebuild after OUI fix | 10.9 MB artifact regenerated | 2026-09-07 |

**Hardware context of verification:** Windows 11, Python 3.12.7, Wi-Fi adapter
(RZ616 Wi-Fi 6E 160MHz) on `192.168.0.0/24`, gateway `192.168.0.1`.

## 3. Known Limitations (accepted for v1)

1. **Windows-only** — `SendARP`/`GetAdaptersInfo` are Windows APIs (per user choice).
2. **Single CIDR per scan** — multi-range queue deferred (roadmap §11).
3. **Embedded OUI covers ~450 prefixes** — full IEEE DB via optional `oui.txt`.
4. **Reverse-DNS is best-effort** — many consumer devices return nothing.
5. **No signed installer** — SmartScreen may warn on first run of the exe.
6. **No CLI-only ARP-cache fallback** — `SendARP` chosen as sole engine by design.

## 4. Backlog / Next Steps

- [ ] Full-subnet live run (`192.168.0.0/24`) by the user; compare against `arp -a`
- [ ] Optional: application icon resource for the exe (PyInstaller `icon=`)
- [ ] Optional: diff view ("new hosts since last scan") — architecture.md §11
- [ ] Optional: Code Signing certificate to silence SmartScreen
- [ ] Optional: GitHub Actions CI matrix (pytest on windows-latest)

## 5. How To Re-run Everything

```bash
# tests
.venv/Scripts/python -m pytest tests/ -v

# rebuild the portable exe (idempotent; recreates venv if missing)
.venv/Scripts/python build.py

# headless scan
.venv/Scripts/python main.py --cli 192.168.0.0/24 --csv out.csv --json out.json

# GUI
.venv/Scripts/python main.py
```
