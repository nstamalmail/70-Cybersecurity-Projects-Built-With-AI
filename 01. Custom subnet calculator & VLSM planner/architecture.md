# Architecture — Custom Subnet Calculator & VLSM Planner

**Version:** 1.0
**Author:** Security Engineering (senior review)
**Status:** Implemented per this document

---

## 1. Executive Summary

A desktop GUI application that performs two related network-engineering tasks:

1. **Subnet Calculator** — given an IPv4 address and a prefix length (CIDR) or dotted-decimal netmask, compute network address, broadcast address, usable host range, host counts, wildcard mask, and binary representations. Also supports equal division of a network into `2^k` subnets.
2. **VLSM Planner** — given a base network and a set of named segments with host requirements, produce an optimal **Variable Length Subnet Masking** allocation: the smallest CIDR block that satisfies each requirement, placed contiguously in descending order of size, with per-segment and overall efficiency metrics.

The application is a **local-only, offline** tool. No network I/O occurs at runtime. All inputs are validated against strict grammars, all persistence is schema-validated JSON, and the domain logic is a pure, side-effect-free core that is fully unit-tested independently of the GUI.

**Deliverables**

| Artifact | Path |
|---|---|
| Architecture doc | `architecture.md` |
| Session state / progress | `state.md` |
| Design decisions & rationale log | `memory.md` |
| Source tree | `src/` |
| Unit tests | `tests/` |
| Portable executable (Windows) | `dist/VLSM-Planner.exe` |

---

## 2. Goals and Non-Goals

### 2.1 Goals

- **G1 — Correctness:** Subnet math must agree with RFC 4632 (CIDR) and the canonical behavior of `ipaddress` on Python ≥ 3.8. Host counts must account for network/broadcast overhead (with RFC 3021 awareness for `/31` and `/32`).
- **G2 — Usability:** Two-tab GUI, copy-paste friendly inputs, tabular results with selectable rows, and one-click export.
- **G3 — Portability:** Single-file Windows executable built with PyInstaller (`--onefile --windowed`); no runtime dependencies beyond a stock Windows 10/11 install.
- **G4 — Security hygiene:** Strict input validation, no dynamic code execution, bounded allocations (defense against resource-exhaustion on hostile files), schema-validated persistence, and local rotating logs.
- **G5 — Testability:** The domain layer is pure Python with zero GUI/OS dependencies; 100% of algorithmic behavior is covered by `unittest`.

### 2.2 Non-Goals (out of scope for v1)

- IPv6 addressing.
- Interactive network diagram / topology canvas.
- Classful (legacy) address classes as a primary feature.
- Multi-user collaboration, cloud sync, or any remote service.
- Auto-discovery of live network state (this is a planning tool, not a scanner).

---

## 3. Security Posture & Threat Model

Reviewed as a security engineer. The tool is offline and local, but desktop software still carries risk surfaces: **malformed input, hostile save-files, and information disclosure in logs/exports.**

### 3.1 Threat model (STRIDE-lite)

| Threat | Mitigation |
|---|---|
| **Spoofing** — user pastes `10.0.0.1; rm -rf` or `../../etc` into an entry | Strict per-field regex validation; free-text fields (segment names) are length-capped and **never** interpreted — names are data, rendered with `str()` only |
| **Tampering** — a crafted `.json` plan file | Persistence layer validates every field: type, range (`0 ≤ prefix ≤ 32`, `0 ≤ hosts ≤ cap`), array bounds (segment count cap), and total-size check before any allocation is performed |
| **Repudiation** — "the tool produced a wrong answer" | Deterministic pure functions + logging of inputs at INFO level; every calculation is reproducible from the logged input tuple |
| **Information disclosure** — plans saved by an admin on a shared machine | Plain JSON is the default format (transparency, no proprietary binary); logs are written to the per-user app-data dir with `0o600`-style intent and rotated; the README documents the file format |
| **Denial of service** — a hostile file with a 100 000-segment plan, or a prefix like `/0` with huge host counts | Hard caps: `MAX_SEGMENTS = 500`, `MAX_HOSTS_PER_SEGMENT = 2^32`, total allocation must fit the base network; allocation loop is bounded and fails fast with a user-facing error |
| **Elevation of privilege** — code execution via `eval`/`exec`/`pickle` | **Forbidden in this codebase.** Persistence uses `json` (data only). Input parsing uses `ipaddress` + regex. No `eval`, `exec`, `pickle`, `shell=True`, or subprocess calls anywhere in `src/` |
| **Physical** — loss of a saved plan | Export to human-readable `.txt` report complements the JSON; both are trivial to back up |

### 3.2 Security invariants (enforced in code, covered by tests)

1. Every IP string must match `^(\d{1,3}\.){3}\d{1,3}$` **and** parse through `ipaddress.IPv4Address` (which rejects leading zeros and out-of-range octets).
2. `0 ≤ prefix ≤ 32`; netmask strings must parse to a valid contiguous mask (`IPv4Network` enforces this).
3. `1 ≤ segment_count ≤ 500`; `0 < required_hosts ≤ 2^32 - 2`.
4. VLSM allocation never allocates beyond the base network's broadcast address — otherwise the plan is rejected with an explicit error.
5. No file write path may be influenced by user input (save dialogs produce the path; the app never derives paths from segment names).
6. All logging is local, size-bounded (rotating handler), and contains no secrets.

---

## 4. Technology Stack & Rationale

| Choice | Rationale |
|---|---|
| **Python 3.12** | LTS-adjacent, batteries included, excellent `ipaddress` stdlib |
| **tkinter + ttk** | Ships with CPython — zero third-party GUI deps → small, stable PyInstaller bundle; native look on Windows |
| **ipaddress (stdlib)** | Canonical, battle-tested IPv4 math; we delegate all bit-twiddling to it |
| **json (stdlib)** | Safe, transparent persistence format (no pickle) |
| **logging (stdlib)** | Rotating file + console handlers, structured message format |
| **unittest (stdlib)** | Zero-dependency test runner; runs headless (no display needed) |
| **PyInstaller 6.x** | Industry-standard one-file Windows bundler; `--onefile --windowed` produces a self-extracting portable exe |

**Deliberately excluded:** numpy (no need), PyQt/PySide (large bundles, licensing), any HTTP client (offline by design).

---

## 5. Layered Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER (src/ui)                    │
│  MainWindow · CalculatorTab · VlsmTab · dialogs · status bar        │
│  Responsibilities: widget layout, event binding, field validation   │
│  feedback, clipboard copy. NO business logic beyond string→domain   │
│  conversion.                                                        │
├────────────────────────────────────────────────────────────────────┤
│                     APPLICATION LAYER (src/app.py)                  │
│  AppController — orchestrates UI↔domain, owns Repository + Logger   │
│  Translates GUI events into service calls; formats results for UI   │
├────────────────────────────────────────────────────────────────────┤
│                        DOMAIN LAYER (src/domain)                    │
│  calculator.py   — pure subnet math (calculate_subnet, divide)      │
│  vlsm.py         — pure VLSM allocator (plan_vlsm)                  │
│  models.py       — dataclasses: SubnetInfo, VlsmSegment, VlsmPlan   │
│  NO imports from ui/ or app/; fully unit-testable headless          │
├────────────────────────────────────────────────────────────────────┤
│                      PERSISTENCE LAYER (src/persistence)            │
│  repository.py   — schema-validated JSON save/load, TXT report      │
│  Handles: atomic writes (temp file + os.replace), strict schema     │
├────────────────────────────────────────────────────────────────────┤
│                        CROSS-CUTTING (src/util)                     │
│  logging_setup.py — rotating file logger, console mirror            │
└────────────────────────────────────────────────────────────────────┘
```

### 5.1 Dependency rule

- `ui → app → domain` and `ui → persistence` (via app).
- `domain` imports **only** stdlib (`ipaddress`, `dataclasses`, `typing`).
- `persistence` imports **only** `domain` (+ stdlib).
- **No reverse edges.** This keeps the core testable and prevents GUI bugs from corrupting math.

---

## 6. Module Reference

### 6.1 `src/domain/models.py`

Immutable value objects:

```python
@dataclass(frozen=True)
class SubnetInfo:
    network: str          # "192.168.1.0/24"
    prefix: int
    netmask: str          # "255.255.255.0"
    wildcard: str         # "0.0.0.255"
    network_address: str
    broadcast_address: str
    first_host: str
    last_host: str
    total_hosts: int      # 2^(32-prefix)
    usable_hosts: int     # RFC 3021-aware
    binary_network: str   # "11000000.10101000.00000001.00000000"
    binary_mask: str

@dataclass(frozen=True)
class VlsmSegment:
    name: str
    required_hosts: int
    prefix: int           # allocated prefix (None ⇒ failed)
    network: str          # allocated network address
    usable_hosts: int     # capacity
    wasted_hosts: int     # capacity − required (≥ 0)

@dataclass(frozen=True)
class VlsmPlan:
    base_network: str
    segments: tuple[VlsmSegment, ...]
    total_required: int
    total_allocated: int  # sum of 2^(32-prefix)
    total_wasted: int
    efficiency: float     # total_required / total_allocated
```

### 6.2 `src/domain/calculator.py`

Pure functions:

| Function | Behavior |
|---|---|
| `parse_ipv4(text) -> IPv4Address` | Regex pre-check + `ipaddress` parse; raises `ValueError` |
| `prefix_from_mask(text) -> int` | Accepts `255.255.255.0` / `255.255.0.0` … ; uses `IPv4Network(f"0.0.0.0/{mask}")`; raises on non-contiguous |
| `netmask_from_prefix(prefix) -> int` | Dotted netmask for a prefix (shared by the UI and CSV results export) |
| `calculate_subnet(ip: str, prefix: int) -> SubnetInfo` | Full subnet info via `IPv4Network(f"{ip}/{prefix}", strict=False)` |
| `divide_network(network: str, parts: int) -> list[SubnetInfo]` | Equal split into `parts ∈ {2,4,…,2^k}`; validates exact power-of-two |
| `network_from_string(net: str) -> IPv4Network` | Parses `a.b.c.d/nn` |

Edge cases handled: `/31` and `/32` (RFC 3021: no network/broadcast overhead; first/last host display adapted), wildcard = bitwise NOT of mask.

### 6.3 `src/domain/vlsm.py` — VLSM algorithm

**Input:** base network `N`, list of `(name, required_hosts)`.
**Output:** `VlsmPlan` or a descriptive error.

```
function plan_vlsm(N, segments):
    validate N; validate each segment (name ≤ 64 chars, 1 ≤ hosts ≤ cap)
    S ← sort(segments, key = required_hosts, descending)      # stability keeps input order for ties
    cursor ← N.network_address
    for s in S:
        p ← minimal prefix such that usable_hosts(p) ≥ s.required
        if p < N.prefix:  FAIL "segment 's' requires more than the base network"
        block_size ← 2 ** (32 - p)
        if cursor + block_size - 1 > N.broadcast_address: FAIL "total demand exceeds base network"
        allocate s at cursor with prefix p
        cursor ← cursor + block_size
    compute totals; efficiency ← required / allocated
    return VlsmPlan
```

**Properties:** contiguous allocation, descending-size ordering (textbook VLSM), greedy-optimal in the sense that each segment gets the smallest block that fits; waste is therefore minimized subject to contiguity.

### 6.4 `src/persistence/repository.py` + `csv_io.py`

- `save_plan(path, plan) -> None` — serialize `VlsmPlan` to JSON; **atomic**: write to `path + ".tmp"`, then `os.replace` (never a half-written file on crash).
- `load_plan(path) -> VlsmPlan` — strict schema validation (types, ranges, caps, total-fit check); raises `PersistenceError` on any violation.
- `export_report(path, plan) -> None` — human-readable `.txt` (header, table aligned with fixed widths, totals, efficiency, timestamp).

**JSON schema (v1):**

```json
{
  "format": "vlsm-plan",
  "schema_version": 1,
  "base_network": "192.168.1.0/24",
  "segments": [
    {"name": "mgmt", "required_hosts": 10, "prefix": 28,
     "network": "192.168.1.0", "usable_hosts": 14, "wasted_hosts": 4}
  ]
}
```

Validation rules: `format` and `schema_version` must match exactly; `base_network` must parse; `1 ≤ len(segments) ≤ MAX_SEGMENTS`; each `prefix ∈ [base.prefix, 32]`; recompute-and-check allocation fit (defends against hand-edited files).

### 6.4.1 `src/persistence/csv_io.py`

- `export_segments_csv(path, rows)` / `load_segments_csv(path)` / `parse_segments_csv(text)` — segment-list round-trip in `name,required_hosts` CSV. Import is lenient (first non-blank row is treated as a header only when its hosts column is non-numeric; headerless files and blank lines are accepted) and enforces the same bounds as the allocator (name length, host range, `MAX_SEGMENTS` cap) so hostile CSVs fail fast.
- `export_results_csv(path, plan)` — allocation result table (segment, required, prefix, network, netmask, usable, wasted) for analysis in spreadsheets.
- Line endings are CRLF (Excel-friendly); writes go through `atomic_write`.

### 6.4.2 `src/persistence/svg_export.py`

- `render_vlsm_svg(plan) -> str` — pure renderer for the address-space map: a horizontal bar spanning the base network; segment blocks with linear-proportional widths; a hatched overlay marking wasted (unused) capacity inside each block; dashed gaps for unallocated address space; below-block labels (name, network/prefix → range end); a legend and totals footer. Output is a fully self-contained SVG (inline styles, XML-escaped names) that opens in any browser.
- `export_svg(path, plan)` — atomic file write via `atomic_write`.
- Overlap protection: minimum rendered block width is capped by `scale × smallest_block_size`, so crowded plans (many tiny blocks) never overlap.

### 6.5 `src/ui/` — tkinter views

- `MainWindow` — `ttk.Notebook` with two tabs, `Menu` (File: Save/Load/Export/Exit; Help: About), persistent status bar, clipboard helpers.
- `CalculatorTab` — entry fields (IP, prefix **or** mask with auto-conversion), results grid (read-only labels), **Equal Division** section (split into 2/4/8/16/32/64 → `ttk.Treeview`), copy-to-clipboard for any result row.
- `VlsmTab` — base network entry; segment table (`Treeview` with name/hosts columns, Add/Delete/Clear); "Plan VLSM" button; results treeview (segment → prefix, network, mask, usable, wasted); summary labels (total required, allocated, wasted, efficiency %); Import/Export CSV buttons (callbacks to the main window); Save/Load/Export bound to menu.
- **Validation UX:** every field is validated on action; errors surface in the status bar and as `messagebox` for blocking errors — never as raw tracebacks.

### 6.5.1 `src/ui/theme.py` + `src/persistence/config.py`

- `apply_theme(root, mode, treeviews)` — light/dark theming via the cross-platform **clam** ttk theme (the Windows "vista" theme cannot be fully styled). Includes hover states (`style.map`), accent buttons, themed notebook tabs, scrollbars, status bar, and `option_add`-based theming for classic `tk.Menu`/`tk.Label` widgets that ttk cannot reach.
- Treeview row striping via `even`/`odd` item tags, with selection re-applied as a `selected` tag on `<<TreeviewSelect>>` (tag backgrounds otherwise hide the selection highlight).
- `src/persistence/config.py` — user preferences (theme) as JSON at `%LOCALAPPDATA%\VlsmPlanner\config.json`; corrupt/missing files degrade to defaults.
- Toggle: **View → Dark theme** (`Ctrl+T`); the choice persists across restarts.
- **Known limitation:** native file dialogs and message boxes remain OS-themed (tkinter cannot style them).

### 6.6 `src/util/logging_setup.py`

- File handler: `%LOCALAPPDATA%/VlsmPlanner/logs/vlsm.log` (fallback: project `./logs/`), `RotatingFileHandler(1 MB, 3 backups)`.
- Format: `2026-09-07T12:00:00Z LEVEL module — message`.
- INFO: calculation inputs & outputs summary; WARNING: validation failures (useful for support); ERROR: unexpected exceptions (traceback included).

### 6.7 `src/app.py`

`AppController` — the only class the UI talks to:

- `calculate(ip, prefix_or_mask) -> SubnetInfo`
- `divide(network, parts) -> list[SubnetInfo]`
- `plan_vlsm(base, segments) -> VlsmPlan`
- `save_plan(path, plan)` / `load_plan(path)` / `export_report(path, plan)`
- Wraps domain exceptions into `UserError` with friendly messages; logs at appropriate levels.

---

## 7. Build & Packaging

### 7.1 PyInstaller

```bash
pyinstaller --noconfirm --clean \
  --onefile --windowed \
  --name "VLSM-Planner" \
  --distpath dist --workpath build \
  main.py
```

- `--onefile`: single self-extracting portable exe → `dist/VLSM-Planner.exe`.
- `--windowed`: no console window (GUI app).
- Output size ≈ 10–12 MB; runs on stock Windows 10/11 x64 without Python installed.

### 7.2 Runtime layout

| Item | Location (exe mode) | Location (source mode) |
|---|---|---|
| Logs | `%LOCALAPPDATA%\VlsmPlanner\logs\` | `./logs/` |
| Saved plans | user-chosen via Save dialog | same |
| Temp files | `os.replace` atomic swap in target dir | same |

---

## 8. Error Handling Strategy

1. **Domain layer** raises typed `ValueError` / custom `PlannerError` with actionable messages ("Segment 'ops' (1200 hosts) does not fit in 192.168.1.0/24").
2. **App layer** catches and re-raises as `UserError(message)`; GUI catches `UserError` → status bar + messagebox; catches `Exception` → log traceback, generic message ("Unexpected error — see log for details").
3. **Persistence** wraps OS/JSON errors in `PersistenceError` with context (path, cause).
4. No bare `except: pass` anywhere; every catch either surfaces to the user or logs.

---

## 9. Testing Strategy

`tests/` uses stdlib `unittest`, runnable with `python -m unittest discover -s tests -v` (headless — never imports `tkinter`).

| File | Covers |
|---|---|
| `test_calculator.py` | Known-answer vectors (RFC examples, /31, /32, classful boundaries, mask→prefix, division into 2/4/8…, invalid inputs) |
| `test_vlsm.py` | Textbook example (e.g., 10.0.0.0/24 → /26,/27,…), exact-fit, wasted-capacity math, overflow rejection, ordering stability, caps |
| `test_repository.py` | Round-trip save/load, schema rejection (wrong format, out-of-range prefix, oversized segment list), atomicity, TXT export content |
| `test_csv_io.py` | Segment CSV round-trip, header detection, quoted names, hostile rows (bad hosts, empty names, row cap), results export + netmask rendering |
| `test_app.py` | Controller error mapping, message quality |
| `test_svg_export.py` | Geometry (proportional widths, gaps, crowd overlap), XML escaping, waste overlay presence/absence, empty plan, file export |
| `test_config.py` | Preference defaults, round-trips, corrupt/invalid config degradation |
| `test_theme.py` | GUI-backed: palette application, clam theme, striping tags, selection tag, toggle |

Run before every build; the build script (`build_exe.bat`) runs tests first and aborts on failure.

---

## 10. Known Limitations & Roadmap

- **v1** (implemented): IPv4-only; contiguous VLSM; JSON/TXT export.
- **v1.x (implemented):** CSV import/export of segment lists and results (`csv_io.py`, D14); SVG address-space diagram (`svg_export.py`, D15); dark theme + UI polish (`theme.py`, `config.py`, D16).
- **v2 candidates:** IPv6 support; non-contiguous "best-fit" allocation mode; undo/redo in segment table; localization.

---

## 11. Verification Checklist (release gates)

- [x] `python -m unittest discover -s tests -v` — all green
- [x] Manual smoke test of both tabs (source mode)
- [x] PyInstaller build completes without warnings for missing modules
- [x] `dist/VLSM-Planner.exe` launches, calculator and VLSM flows work
- [x] Hostile input checks: `1.2.3.4/33`, `999.1.1.1`, `a.b.c.d`, non-contiguous mask `255.0.255.0`, oversized plan JSON — all rejected gracefully