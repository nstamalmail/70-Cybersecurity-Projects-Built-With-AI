# Memory — ARP Scanner

> Durable engineering memory for this project. Read before changing anything
> in `core/` or the build. Each entry says **what**, **why**, and **what
> breaks if you ignore it**. Companion: `state.md` (current status),
> `architecture.md` (design).

---

## 1. Architectural Decisions (ADR-style, immutable without re-review)

### D1 — Scan engine: Windows `SendARP` via ctypes (hybrid), NOT Scapy
- **Decided:** 2026-09-07, by user choice from three options.
- **Why:** zero external dependencies (no Npcap driver install), no admin
  rights, single ~11 MB portable exe. Scapy would need Npcap + admin and a
  25 MB+ bundle.
- **Trade-off accepted:** Windows-only; no raw packet crafting (so no future
  mitM/spoofing features in this tool — by design, see architecture.md §10).
- **If you must revisit:** swap `core/engine.py` only; the rest of the stack
  (models, exporters, GUI) is engine-agnostic by layering.

### D2 — GUI: plain Tkinter/ttk, NOT CustomTkinter/PySide
- **Decided:** 2026-09-07, by user choice.
- **Why:** stdlib-only, smallest exe, most robust PyInstaller packaging.
- **Consequence:** visual polish is limited; theming was deferred (roadmap).

### D3 — OUI database is embedded (~450 curated prefixes), optionally
extended by IEEE `oui.txt` placed next to the exe/app.
- **Why:** self-contained exe (G4); full DB is 40k+ lines and would bloat the
  binary by ~1 MB for marginal benefit.
- **Rule:** `OUI_DB.setdefault()` on merge — embedded entries win; the file
  must never be able to *break* startup (all parsing is try/except).

### D4 — Layering: `core/` never imports `ui/`; Windows calls exist only in
`core/interface.py` + `core/engine.py`.
- **Why:** headless CLI (G6) and testability; single audit surface for the
  ctypes security review (architecture.md §10.6).
- **Enforcement:** review discipline — no lint rule configured. Keep it true.

### D5 — Exports write only where the user explicitly picked a path
(`filedialog`), CSV is UTF-8 **with BOM** (`utf-8-sig`) so Excel opens it
without mojibake. JSON holds full metadata, CSV holds the flat table.

---

## 2. Platform Gotchas (each one actually bit or nearly bit this build)

### G-1 — `IP_ADAPTER_INFO` struct sizes are NOT the obvious ones
Windows headers declare the buffers 4 bytes larger than the "MAX" constants:
```
AdapterName  = MAX_ADAPTER_NAME_LENGTH(256) + 4 = 260 bytes
Description  = MAX_ADAPTER_DESCRIPTION_LENGTH(128) + 4 = 132 bytes
```
On x64 `sizeof(IP_ADAPTER_INFO)` must be **656**. If you change the ctypes
struct and get garbage adapters/GUIDs, check sizes first. (The wrong sizes
parse "successfully" — silently wrong — which is the nasty part.)

### G-2 — `SendARP` IPAddr byte order: little-endian memory layout of the
dotted quad (the `inet_addr()` convention), i.e. `127.0.0.1` → `0x0100007F`.
`int(ipaddress.IPv4Address(ip))` gives the *big-endian* integer → probes
**byte-swapped addresses** and finds nothing, with zero error messages.
Correct conversion (what we ship):
```python
struct.unpack("<I", socket.inet_aton(ip))[0]
```
Caught during this build by pre-deploy review; would have produced a
completely "working" GUI that always reported zero hosts.

### G-3 — `/31` networks: `ipaddress.hosts()` behavior differs across Python
versions. We special-case prefixlen ≥ 31 explicitly (RFC 3021 for /31, the
single address for /32) instead of trusting `hosts()`. Don't "simplify" this.

### G-4 — Windows consoles default to cp1252: any `print()` of `→`, `—`, `…`
crashes the CLI with `UnicodeEncodeError` *after the useful work completed*
— worst possible time. Rule: **CLI/stdout strings are ASCII**; we also call
`sys.stdout.reconfigure(errors="replace")` defensively. The GUI may use
Unicode (Tk handles it).

### G-5 — Tkinter thread safety: the scanner thread may only touch
`queue.Queue`; the UI drains it on `root.after(100, ...)`. Direct widget
mutation from a worker thread "usually works" and then randomly crashes.
This is the single most violated Tk rule; the pattern lives in
`ui/app.py: _drain_queue()` — copy it, don't improvise.

### G-6 — Modal dialogs in tests hang CI forever. Every `messagebox.*` call
path reachable from a test must be monkeypatched to a no-op first
(see `tests/test_gui.py`). If you add a dialog to an event handler, the GUI
test suite will silently hang — patch it in the test at the same time.

### G-7 — PyInstaller onefile shows **two** processes in `tasklist`
(bootloader + payload). Don't mistake this for a double-launch bug; kill
both. Also: `console=False` means the exe has **no stdout** — verify via
GUI/process-liveness or the CLI, never via exe console output.

### G-8 — Locally-administered MACs (2nd hex digit ∈ {2,6,A,E}) are reported
as "Randomized (locally administered)" — modern phones/tablets randomize
per-SSID MACs, so "unknown vendor" on Wi-Fi is usually *privacy*, not a
lookup failure. Keep this string stable; users build workflows on it.

### G-9 — `expand_targets` returns a **new sorted list**; `scan()` removes
the local machine's IP from that private copy. If you ever cache/share the
targets list between calls, the exclusion becomes a side effect. Keep the
current copy-by-value semantics.

### G-10 — Progress lines in the CLI use `\r` + `ljust()` over the previous
line length to overwrite cleanly. If output looks duplicated in some
terminals, it's the console, not the logic.

---

## 3. Do-Not-Regress List (verified behaviors; re-run after touching these)

| Behavior | How to verify |
|---|---|
| `_ip_to_u32("127.0.0.1") == 0x0100007F` | `pytest tests/test_core.py::TestIpToU32` |
| Self-probe + gateway probe return MACs | scripts in `state.md` §5 |
| CLI survives cp1252 console | run `main.py --cli <ip>/32` in cmd.exe |
| GUI smoke incl. `done` event re-sort | `pytest tests/test_gui.py` |
| exe builds & launches | `.venv/Scripts/python build.py`, then run `dist/ARPScanner.exe` |
| 26/26 tests green | `.venv/Scripts/python -m pytest tests/` |

## 4. Glossary (for future maintainers joining cold)

- **SendARP** — Windows iphlpapi call that asks the OS to resolve an IPv4
  address to a MAC via ARP; synchronous, per-call timeout, no raw sockets.
- **GetAdaptersInfo** — iphlpapi enumeration of IPv4 adapters (linked list).
- **OUI** — first 3 MAC octets, IEEE-assigned vendor prefix.
- **APIPA** — `169.254.0.0/16` self-assigned address = "no DHCP", skip it.
- **onefile** — PyInstaller mode: single self-extracting exe.

## 5. Session Log

- **2026-09-07 (v1.0 build session):** architecture written → core/UI/CLI
  implemented → 2 pre-ship bugs caught by review (G-2 byte order, own-IP not
  excluded) → 26 tests green → hardware-verified SendARP on Wi-Fi → exe
  built (10.9 MB) and launch-smoke-tested → OUI extended with MediaTek/
  TP-Link prefixes observed on this network → exe rebuilt. No open defects.
