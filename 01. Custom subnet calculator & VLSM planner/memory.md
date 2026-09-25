# Memory — Design Decisions & Rationale Log

> Purpose: preserve *why* things are the way they are, so future sessions don't second-guess or regress prior decisions. Append new entries; never rewrite history entries (clarify with a new entry instead).

**Project:** Custom Subnet Calculator & VLSM Planner (v1.0.0)

---

## Decision Log

### D1 — Pure domain layer, GUI as a thin shell
- **Decision:** All subnet math and VLSM allocation live in `src/domain/` with zero imports from `ui/`/`app/`/`persistence/`.
- **Why:** Testability (50 headless unit tests), correctness (a GUI refactor can never corrupt math), and reproducibility (same input → same output, guaranteed by pure functions).
- **Trade-off:** Slightly more code for wiring; accepted.

### D2 — Use stdlib `ipaddress`, not hand-rolled bit math
- **Decision:** Delegate all IPv4 parsing, network/broadcast derivation and mask handling to `ipaddress`.
- **Why:** It is canonical, rejects malformed input (e.g. leading zeros in octets, non-contiguous masks) and is already battle-tested. Writing our own parser is a security risk (RFC 4632 edge cases).
- **Trade-off:** We wrap it with friendlier error messages; `strict=False` is used deliberately so host bits in inputs are tolerated (typical user behaviour).

### D3 — RFC 3021 handling for /31 and /32
- **Decision:** `usable_host_count` returns 2 for /31 and 1 for /32 instead of the naive `2^(32-p) − 2`.
- **Why:** Point-to-point links (RFC 3021) legitimately use all addresses in a /31; a /32 addresses a single host. Naive math would report 0 usable hosts for both, which is wrong for planners.
- **Consequence:** VLSM planner can allocate /31 and /32 blocks; tests pin this behaviour.

### D4 — Classic contiguous VLSM algorithm (descending-size order)
- **Decision:** Sort segments by required hosts descending (stable), allocate the smallest fitting block at the current cursor, reject when the base network overflows.
- **Why:** This is the textbook algorithm network engineers expect; results are deterministic and explainable. Non-contiguous best-fit packing was considered but produces harder-to-read plans.
- **Trade-off:** Contiguity can waste addresses vs. best-fit; acceptable for v1, flagged as a v2 mode in architecture.md §10.

### D5 — Efficiency metric = required / allocated address space
- **Decision:** `efficiency = total_required / total_allocated` where `total_allocated` is the sum of block sizes (not usable host counts).
- **Why:** It reflects real address-space consumption, including network/broadcast overhead. Note the subtlety: even a "perfect" plan can't hit 100% unless every block is /31 or /32 — the tests document this (232/240 ≈ 96.7% for zero-waste /25…/28).
- **Consequence:** `wasted_hosts = usable − required` measures capacity waste; efficiency measures address-space waste. Both are shown in the UI.

### D6 — JSON persistence with re-derivation, not trust
- **Decision:** Save the ground truth (`base_network`, `name`, `required_hosts`); on load, ignore stored derived fields and re-run the allocator.
- **Why:** Defense against hand-edited or corrupted files (architecture.md §3). A crafted file that claims prefix /23 inside a /24 base is recomputed to its true value or rejected — never trusted.
- **Trade-off:** Derived fields are stored for human readability of the file but are purely informational.

### D7 — Atomic writes (temp file + `os.replace`)
- **Decision:** Save/export write to a temp file in the destination directory, flush + fsync, then `os.replace`.
- **Why:** A crash mid-write must never leave a half-written plan or report. `os.replace` is atomic on the same filesystem (NTFS included).
- **Trade-off:** Two files exist momentarily; invisible to users.

### D8 — tkinter over PyQt/PySide/electron
- **Decision:** tkinter + ttk.
- **Why:** Ships with CPython → zero GUI runtime deps → small, reliable PyInstaller bundle (~10 MB), no licensing concerns, native Windows look.
- **Trade-off:** Less polished theming; accepted for an engineering tool.

### D9 — Strict caps to bound hostile inputs
- **Decision:** `MAX_SEGMENTS = 500`, host counts in `[1, 2^32 − 2]`, prefix in `[0, 32]`, name length ≤ 64.
- **Why:** A 100 000-segment plan file or a segment demanding 2^40 hosts must fail fast instead of consuming memory or looping forever (threat: DoS via crafted file, architecture.md §3.1).
- **Consequence:** These constants are exported from `src/domain/vlsm.py` and enforced in both the allocator and the repository loader.

### D10 — `UserError` facade for the GUI
- **Decision:** The app controller converts domain `PlannerError`/`PersistenceError` into a single `UserError` type with a display-safe message; the GUI only ever shows `str(UserError)` in dialogs/status bar.
- **Why:** Prevents raw tracebacks or internal detail leaking to users; keeps error handling policy (architecture.md §8) centralized.

### D11 — Logging location differs by mode
- **Decision:** Packaged exe logs to `%LOCALAPPDATA%\VlsmPlanner\logs\vlsm.log` (rotating, 1 MB × 3); source mode logs to `./logs/`.
- **Why:** A portable exe may be run from a read-only or temp directory; per-user AppData is writable and survives. Rotating handler bounds disk growth.
- **Consequence:** "Unexpected error — see log" messages can point at the right file (About dialog shows the path).

### D14 — CSV import/export of segment lists (stdlib `csv`, lenient parse)
- **Decision:** Segment lists round-trip through CSV (`name,required_hosts`), with an additional export of the allocation *results* table. Parsing lives in `src/persistence/csv_io.py`; `AppController` exposes `import_segments` / `export_segments` / `export_results_csv`; UI has buttons on the VLSM tab plus File-menu items.
- **Why:** Spreadsheet-driven planning is how engineers actually prepare segment lists; CSV is the lowest-friction interchange format and needs no extra deps.
- **Key choices:**
  - Only the FIRST non-blank row may be treated as a header, and only if its hosts column is non-numeric — so headerless user files parse, and genuinely bad rows still raise with a line number.
  - All bounds from the allocator are enforced at import (name length, host range 1..2^32−2, MAX_SEGMENTS cap) — a hostile CSV cannot bypass validation.
  - Line terminator is CRLF (Excel-friendly); `atomic_write` now opens with `newline=""` so the writer controls line endings exactly.
- **Bug caught during this work:** text-mode `open(..., newline=None)` on Windows translates `\n` → `\r\n`, so csv_io's explicit `\r\n` was written as `\r\r\n` (double carriage return). Fixed centrally in `atomic_write` by disabling translation.

### D15 — SVG diagram export: address-space map with waste hatching
- **Decision:** `File → Export diagram (SVG)…` renders the VLSM allocation as a self-contained SVG: one horizontal bar for the base network, segment blocks whose width is proportional to block size (linear scale), hatched overlay on the right end of a block marking wasted (unused) capacity, light dashed gaps for unallocated address space, below-block labels, a legend and totals. Pure renderer in `src/persistence/svg_export.py` (`render_vlsm_svg`), file write via `atomic_write`.
- **Why:** A picture of the address space is the fastest way to review a plan for waste and fragmentation; SVG is vector, printable, and opens everywhere with zero deps.
- **Key choices:**
  - Widths are linear (block ∝ 2^(32−prefix)), but `min_w` is capped by `scale × smallest_block_size` so crowded plans (e.g. hundreds of /32s) never overlap.
  - XML escaping via `xml.sax.saxutils.escape` for all names (security invariant).
  - Narrow blocks (<40px) get no below-block label; the full range label needs ≥100px — avoids neighbor overlap.
- **Bugs caught in tests:** legend swatch rects were drawn at negative y (clipped off-canvas) — fixed by deriving rect y from the text baseline; and `min_w = avail/n` was wrong for crowded plans (forced widths still overlapped) — replaced with the `scale × smallest_block` rule.

### D16 — Dark theme + UI polish: clam engine, persisted preference, striped trees
- **Decision:** A theme engine (`src/ui/theme.py`) with light/dark palettes, applied via the cross-platform **clam** ttk theme (the Windows "vista" theme can't be fully styled). Toggle lives in a new **View → Dark theme** menu checkbutton (`Ctrl+T`); the choice persists to `%LOCALAPPDATA%\VlsmPlanner\config.json` (`src/persistence/config.py`).
- **Why:** Network engineers often work late/on dark setups; a themed app also looks more finished. Preference persistence means the choice survives restarts.
- **Key choices:**
  - clam is used for **both** palettes so the two themes differ only in colors, never layout.
  - `tk.Menu` widgets can't be ttk-styled, so they're themed via `option_add` (menu background/foreground/active). Classic `tk.Label`s (results grid) get `*Label.background/foreground` the same way.
  - Treeview row striping uses even/odd item tags; because tag backgrounds otherwise override the selection highlight, selection is re-applied as a `selected` tag on `<<TreeviewSelect>>`.
  - Primary action buttons (Calculate, Divide, Add segment, Plan VLSM) use `Accent.TButton`; the muted hint label uses a `Muted.TLabel` style instead of a hardcoded `#666666`.
  - Preferences degrade gracefully: missing/corrupt config → light theme, never a crash.
- **Caveat (accepted):** native file dialogs and message boxes stay OS-light in dark mode (tkinter limitation); menus are themed, dialogs are not.

### D13 — GUI smoke testing catches what unit tests can't
- **Decision:** Before release, the GUI is exercised programmatically (construct `MainWindow`, drive `_calculate`/`_divide`/`_run_plan` with a real Tk root, `update()`, assert on widget state) plus a launch-and-kill smoke test of the packaged exe.
- **Why:** Two real startup-breaking bugs shipped despite 50/50 green unit tests:
  1. `readonlybackground` is a *tk.Entry* option, not a *ttk.Entry* option → `TclError: unknown option` at startup (caught by the exe launch test).
  2. In `VlsmTab`, the attribute `self._plan` (the plan object) shadowed the `_plan()` method → `TypeError: 'NoneType' object is not callable` when clicking "Plan VLSM". Renamed the method to `_run_plan`.
- **Consequence:** The release gate now includes an automated GUI-flow check, not just unit tests (state.md §5; the domain stays unit-tested headless, the UI gets its own smoke path).

### D12 — Logging level per error class
- **Decision:** Expected, user-driven failures (missing file, invalid JSON, bad input) log at WARNING; truly unexpected exceptions log at ERROR with a traceback.
- **Why:** Keeps the log actionable — a user cancelling a save dialog shouldn't produce scary ERROR entries (observed during smoke testing; fixed before release).

---

## Rejected alternatives

| Idea | Why rejected |
|---|---|
| numpy for bit ops | Overkill; `ipaddress` + ints suffice; numpy would bloat the exe |
| pickle persistence | Unsafe (arbitrary code execution on load) — violates security invariants |
| PyQt6 | +50 MB exe, GPL/commercial licensing friction, more code |
| Electron/web app | Way out of proportion for a local utility; Node runtime not desired |
| Live network scanning | Out of scope: this is a *planning* tool, not a scanner (no network I/O at all) |
| Non-contiguous best-fit as default | Harder to read plans; kept as future opt-in mode |

---

## Open questions for next sessions

1. Should efficiency be reported per-segment as well? (Currently plan-level only.)
2. Do users want CIDR-style wildcard (`/8`) or dotted wildcard in exports? (Currently dotted, e.g. `0.0.0.255`.)
3. Windows Defender/SmartScreen may warn on unsigned PyInstaller exes — worth documenting in a README for end users?