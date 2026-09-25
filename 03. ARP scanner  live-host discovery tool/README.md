# ARP Scanner — Live-Host Discovery (GUI)

Windows ARP scanner with a Tkinter GUI that finds live hosts on your local
IPv4 subnet using the Windows `SendARP` API.

**No Npcap. No admin rights. No Python needed** (for the exe).

> ⚠️ **Authorized use only.** Scanning networks you don't own or administer
> may be illegal. This tool is for inventory of your own network.

## Quickstart (portable exe)

1. Grab `dist/ARPScanner.exe` (10.9 MB, single file).
2. Copy it anywhere and double-click.
3. Pick your adapter → click **▶ Scan** → live results appear.
4. **Save CSV / Save JSON** to export.

## Quickstart (from source)

```bash
python -m venv .venv
.venv/Scripts/pip install pytest pyinstaller   # dev-only; runtime is stdlib
.venv/Scripts/python main.py                   # GUI
```

Headless CLI:

```bash
.venv/Scripts/python main.py --cli 192.168.0.0/24 --csv out.csv --json out.json
```

Rebuild the exe:

```bash
.venv/Scripts/python build.py                  # → dist/ARPScanner.exe
```

## Features

- Adapter auto-detection (default route adapter preselected, CIDR prefilled)
- Streaming scan results (rows appear as hosts answer, no waiting)
- Vendor identification via embedded OUI DB (~450 prefixes; drop a full IEEE
  `oui.txt` next to the app to extend it)
- Reverse-DNS hostname resolution
- Sortable columns (click headers), row copy on double-click
- CSV (Excel-friendly UTF-8 BOM) and JSON export
- Cooperative stop; UI never freezes (scanner runs on a daemon thread)
- Headless CLI mode for scripting (`--cli CIDR`)

## Requirements

- **exe:** Windows 10/11 x64. Nothing else.
- **source:** Python 3.10+ (developed on 3.12) with Tkinter (standard on
  python.org Windows builds). Runtime deps: **none**.

## Project docs

| File | Purpose |
|---|---|
| `architecture.md` | Full design: layers, APIs, data flow, packaging, security review |
| `state.md` | Current build status, verification log, backlog |
| `memory.md` | Durable decisions + platform gotchas (read before touching `core/`) |

## Tests

```bash
.venv/Scripts/python -m pytest tests/ -v
```

26 tests: CIDR math, byte-order conversion, OUI lookup, models, exporters,
GUI smoke (auto-skip when no display).
