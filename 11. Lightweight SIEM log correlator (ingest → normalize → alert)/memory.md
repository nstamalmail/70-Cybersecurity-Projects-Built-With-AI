# Memory — Lightweight SIEM Log Correlator

> Project memory: context, decisions, rationale, and gotchas. Read before
> changing anything. Companion docs: `architecture.md`, `state.md`.

## Project context

Built on request: a **lightweight SIEM log correlator** (ingest → normalize →
alert) delivered as a **GUI-based Python solution plus a portable .exe**, with
`architecture.md`, `state.md`, and `memory.md` maintained. Acted in the role of
a senior security developer. Work began in an empty directory; everything here
was written from scratch.

## Non-negotiables locked in

1. **Zero third-party runtime dependencies.** The app runs on the Python
   standard library alone (`tkinter`, `sqlite3`, `socket`, `queue`,
   `threading`, `json`, `re`, `dataclasses`, `argparse`). This is what makes
   the exe small (~11 MB), dependency-drift-free, and portable. Any new feature
   must stay stdlib-only unless explicitly agreed otherwise.
2. **Portable data.** Runtime data lives in `<app dir>/data/` (exe dir when
   frozen, project root from source), so the whole tool moves on a USB stick.
   Falls back to `%APPDATA%\SIEMCorrelator` only if the folder is unwritable.
3. **Security posture:** log lines are untrusted input — regex parsing only,
   `errors="replace"`, no eval, no shell, parameterized SQL everywhere, bounded
   queues, ring buffers cap memory.

## Key decisions & why

### GUI framework: Tkinter over PySide6/PyQt
- Tkinter ships with Python → keeps the zero-dep promise and the exe tiny.
- Qt adds ~100 MB to the bundle and licensing questions — wrong trade for a
  "lightweight" SIEM.
- Accepted cost: a plainer look; compensated with ttk tabs, severity colors,
  and a Canvas severity chart.

### Threading model: ingest threads → bounded queue → single processor thread
- Correlation (windows, sequences) needs in-order processing; one consumer
  makes that deterministic and cheap.
- GUI updates arrive over a second queue polled with `root.after()` — **Tk
  widgets are only ever touched on the main thread**. This is the #1 rule for
  Tk multithreading and it is enforced by construction (callbacks put to a
  queue, never call widgets).
- Shutdown: stop `Event` → sources exit → processor drains → joins with
  timeout. SQLite shared across threads with `check_same_thread=False` + a lock.

### Rule engine: three rule types + dedup
- `regex` (single event), `threshold` (N matches / window / group key),
  `sequence` (deterministic automaton: step i → step i+1, step 0 restarts,
  window expiry resets). Fail→success is the canonical sequence detection.
- Dedup: per `(rule_id, group_key)` cooldown suppresses alert storms while
  keeping every distinct incident visible.
- Rule edits hot-reload the engine (`reload_rules`), which intentionally resets
  in-memory window/sequence state — documented in `state.md`.

### Normalization: auto-detect, message = full raw line
- Parser chain first-match-wins (JSON → Syslog → Common Log → CEF → K=V →
  plain). Rules match against `message` (the **full raw line**) for
  predictability; structured values live in `fields` (e.g. `src_ip`, `status`).
- Timestamps: parsed from the log when possible, else receive time — sample
  data demonstrates both paths.

### File tailing: poll-based, not watchdog
- No dependency; starts at EOF on attach (or reads the whole file when
  `start_at_end=False`); detects rotation via size shrink or inode/device
  change and re-reads the new file. Poll interval in config.

### Windows Event Log source: wevtutil, not pywin32
- **Zero-dep rule** → no `pywin32`/`wmi`. `wevtutil qe <channel> /f:xml /c:100
  /rd:true` is present on every Windows since Vista and needs no install.
- Tail semantics via `EventRecordID` bookmark: attach stores the max ID, later
  polls emit only higher IDs, oldest→newest so correlation stays in order.
- Each event is rendered as a **single Key=Value line** (`EventID=…
  Provider=… Computer=… Message=…`). This is the key trick: the existing KVP
  normalizer turns it into `fields` and every rule (which matches `message` or
  a field) works on Windows events without any parser changes. Numeric Level is
  mapped to its name (`2`→`Error`) so keyword severity inference classifies it.
- `/r:true` (message rendering) fails with RPC 1722 in restricted sessions;
  the source retries without it and keeps working (structured data only).

### Webtail picker: preview before you tail
- `Tail file…` opens a dialog showing the last ~30 lines of the chosen file
  (like a webtail UI) and defaults to follow-only-new-lines. Unchecking
  ingests the existing content too (`start_at_end=False`).

## Gotchas recorded (read these!)

1. **`field` shadowing in dataclasses** — a dataclass member named `field`
   (`field: str = "message"`) shadows the `from dataclasses import field`
   import *inside the class body*. Caused `TypeError: 'str' object is not
   callable` at `field(default_factory=...)`. Fixed by aliasing the import:
   `from dataclasses import field as dataclass_field`. If you add dataclass
   fields, watch for this.
2. **Walrus in keyword args** — `row=r := r + 1` inside a `.grid(...)` call is
   a SyntaxError; expanded to explicit increments. Avoid walrus in keyword
   positions.
3. **Windows console encoding** — printing em dashes/arrows to cp1252 consoles
   shows mojibake (`�`). GUI and log files (utf-8) are fine; keep *summary/log*
   strings ASCII to keep headless output clean.
4. **PyInstaller onefile** — onefile exes are self-extracting: slower first
   launch and occasional AV heuristics flags. Accepted for portability; if that
   becomes a problem, switch to `--onedir` or sign the binary. The exe must
   write next to itself, hence the writability probe in `config.data_dir()`.
5. **`main.py --data-dir`** — must pass the same dir to `load_config`, else a
   stray project-root `data/config.json` is created (fixed; keep it that way).
6. **Sequence automaton subtlety** — an event that matches step 0 *restarts*
   the attempt (handles repeated failures), and window expiry resets state.
   Test with `tests/smoke_test.py` when touching this.
7. **`wevtutil` XML has no root element** — it emits sibling `<Event>`
   elements, so `ET.fromstring` fails with ParseError. Wrap in a synthetic
   `<Events>…</Events>` before parsing (harmless if a root already exists).
8. **`wevtutil` output encoding** — redirected output is UTF-16LE with BOM on
   Windows; `_decode_wevtutil` checks the BOM, falls back to UTF-8, then
   UTF-16. Test fixtures use `xml.encode("utf-16")`.
9. **Git Bash mangles `/f:xml`** — MSYS path conversion rewrites leading-slash
   args (`/f:xml` → `F:/xml`) and `wevtutil` reports "Too many arguments".
   Always test wevtutil from Python subprocess (args pass through verbatim),
   never from bash with `/flag` style args.
10. **Unnamed `<Data>` elements collide** — EventData `<Data>` without a
    `Name` attribute would overwrite each other in a dict; index them
    (`Data1`, `Data2`, …). Skip the `Binary` blob (huge hex noise).
11. **pack vs grid in one frame** — path widgets inside `path_row` are
    pack-managed; calling `.grid()` on them raises `TclError: cannot use
    geometry manager grid … already managed by pack`. Show/hide with
    `pack`/`pack_forget` for pack-managed children.
12. **Dataclass field order** — new `SourceConfig` fields (`start_at_end`,
    `channel`) were appended *after* the existing defaults so all current
    call sites stay positional-compatible.

## Verification conventions

- `python tests/smoke_test.py` must stay **ALL PASS** — it asserts 5
  detections (threshold, regex ×2, sequence, threshold-by-ip), exact alert
  counts (dedup), severities, and zero false positives on benign lines.
- GUI changes: construct `App` with a temp DB, `after(2000, app._on_close)`,
  `mainloop` — proves widget construction/teardown.
- Exe changes: build, launch, confirm it stays alive and creates `data/`
  next to itself.

## Out of scope / parked ideas

- Multi-user/RBAC, agents, TLS syslog, distributed correlation — extension
  points in `architecture.md` §8. If scoped in later, revisit the threading and
  storage layers first.
- Qt-based prettier UI was deliberately rejected (see above).

## Timeline

- v0.1 built and verified in one session (Sep 7, 2026): architecture doc →
  stdlib implementation → headless smoke test → GUI smoke → PyInstaller build →
  exe launch test → state/memory docs. See `state.md` for the verified
  checklist.
- v0.2 (same day): Windows Event Log source (`winevt` via wevtutil, no
  pywin32), webtail-style file picker (`TailDialog` with preview +
  follow-new-lines), `start_at_end` file option, Windows 4625 seed rule, new
  ingest unit tests, docs updated, exe rebuilt.