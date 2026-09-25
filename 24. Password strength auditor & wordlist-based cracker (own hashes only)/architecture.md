# architecture.md — Password Strength Auditor & Wordlist-Based Cracker (own hashes only)

- **Project:** `HashArmor` — a defensive, offline password security workbench
- **Version:** 1.0.0 · **Status:** Architecture frozen for v1.0 implementation
- **Reviewed:** Senior security developer pass — 2026-09-08
- **License:** MIT · **Classification:** Defensive security tooling (dual-use-safe)

---

## 1. Purpose & Scope

HashArmor is a **defensive password security workbench** for auditing password hash
databases **that the operator owns or is explicitly authorized to test** (your own
accounts, your own user database, your own lab/test hashes).

### In scope (v1.0)

| Capability | Detail |
|---|---|
| Hash ingestion | Paste, file picker, or directory scan of hash files (`hash[:salt][:label]` lines, `#` comments) |
| Hash identification | Auto-detect MD5 / SHA-1 / SHA-256 / SHA-512 / NTLM / MD4 / SHA-512-crypt (rounds honored) |
| Cracking modes | Wordlist · Wordlist+Rules · Mask (brute force) · Combinator |
| Rule engine | hashcat `best64`-compatible subset (51 operations), comment/blank aware |
| Mask engine | `?l ?u ?d ?s ?b ?a` placeholders, presets (4-digit, 6-digit, 8-digit), candidate cap 1,000,000 |
| Strength audit | NIST SP 800-63B aligned checks + Shannon entropy + zxcvbn-style pattern feedback |
| Reports | HTML (self-contained, no CDN) + CSV + JSON, deterministic ordering |
| Sessions | Checkpoint/restore with progress, rate, ETA; survives app restart |
| Packaging | Portable one-file Windows EXE via PyInstaller (`--onefile --noconsole`) |

### Out of scope (v1.0)

- Distributed/network cracking, GPU (OpenCL/CUDA) kernels, rainbow tables
- Live-system credential extraction (no SAM, LSASS, `/etc/shadow`, `vshadow`)
- Cloud services, APIs, auto-update, or any telemetry whatsoever

> **Design stance:** this is an *auditor*, not a weapon. Every control in the UX exists
> to keep the operator inside the legal envelope — see §11.

---

## 2. Guiding Principles

1. **Legal compliance by construction** — explicit gates; cracking stays disabled until accepted.
2. **Offline-only** — zero network calls at runtime; no telemetry, no auto-update.
3. **Transparency** — every computation deterministic, inspectable, reproducible.
4. **Fail-closed** — errors disable actions; nothing silently skipped.
5. **Responsive GUI** — single worker thread + `event_generate` back to the Tk loop; never
   block the main thread with hashing work.
6. **Std-lib only runtime** — no third-party runtime deps. Hashcat-style semantics and RFC
   1320 MD4 are reimplemented faithfully and pinned by unit tests as the proof.
7. **Least privilege** — writes confined to one writable `base_dir`; reads only from paths
   the user explicitly selects.
8. **No plaintext persistence by default** — cracked plaintexts live in memory and
   (optionally) in session checkpoints under the user's own base dir; documented, local, only.

---

## 3. System Context

```
                        ┌─────────────────────────────────────┐
   Hash files  ────────▶│           HashArmor GUI             │──────▶ HTML/CSV/JSON reports
   Wordlists   ────────▶│      (Tkinter, single process)      │
   Rule files  ────────▶│                                     │
                        │  ┌────────────┐   ┌──────────────┐  │
                        │  │  GUI thread│◀──│ Worker thread│  │
                        │  └─────┬──────┘ e │  (one at a   │  │
                        │        │ event_generate       time) │  │
                        │        ▼                ▼          │
                        │  ┌──────────────────────────────┐  │
                        │  │        core package          │  │
                        │  │ parser·attacks·policy·report │  │
                        │  └──────────────────────────────┘  │
                        └──────────────────┬──────────────────┘
                                           ▼
                                writable base_dir only
                        (sessions/ · reports/ · wordlists/)
```

Single process, two threads (Tk main + one worker). No multiprocessing in v1.0 — the GIL
caps pure-Python hashing throughput anyway — but `AttackEngine` exposes a `parallelism`
hook so a future `ProcessPoolExecutor` scale-out is additive, not a rewrite.

---

## 4. Module Map (target tree)

```
hasharmor/
├── main.py                     # entrypoint → gui.app.run()
├── core/
│   ├── __init__.py             # version, license constants
│   ├── hashes.py               # hasher registry, byte seeding, HexTarget adapter
│   ├── md4.py                  # RFC 1320 pure-Python MD4 (verified vectors)
│   ├── parser.py               # line → HashRecord; registry; identified/plain text export
│   ├── wordlists.py            # builtin + external wordlist provider (utf-8 tolerant)
│   ├── rules.py                # hashcat-style rule engine (51 ops)
│   ├── policy.py               # NIST SP 800-63B aligned strength audit
│   ├── attack.py               # AttackEngine: dictionary/rules/mask/combinator + checkpoints
│   ├── session.py              # SessionState: progress, rate, ETA, checkpoint dict
│   ├── exporter.py             # HTML + CSV + JSON reports
│   └── selftest.py             # self_test() → (bool, report string)
├── gui/
│   ├── __init__.py
│   ├── theme.py                # palette, fonts, helpers (hex→tk colors, mono/setup fonts)
│   ├── components.py           # ProgressBar (smooth + % label), LegalBanner, toast helper
│   ├── tabs/
│   │   ├── __init__.py
│   │   ├── audit_tab.py        # load hashes → per-record strength table + verdicts
│   │   ├── crack_tab.py        # attack config, legal gate, start/stop, live crack log
│   │   ├── report_tab.py       # in-window HTML preview + open-in-browser + export
│   │   └── settings_tab.py     # base_dir, wordlist dir, theme, session mgmt
│   └── app.py                  # Tk root, Notebook, statusbar, worker lifecycle
├── tests/
│   └── test_core.py            # pytest suite incl. RFC 1320 vectors
├── assets/
│   └── wordlists/
│       ├── weak_100.txt        # synthetic educational list (NOT real breach data)
│       ├── rockyou_sample.txt  # small synthetic sample (NOT real breach data)
│       └── best64.rule         # hand-written best64-compatible subset
├── docs/
│   ├── architecture.md         # this file
│   ├── state.md                # live build state, decision log, verification ledger
│   └── memory.md               # durable memory: lessons, pitfalls, style, ethics
├── requirements.txt            # build-time only (pyinstaller); runtime is stdlib
├── pyproject.toml              # metadata
├── build_exe.ps1               # one-file exe build (Windows)
├── build_exe.sh                # same for Linux/macOS
└── README.md
```

---

## 5. Core Package Design

### 5.1 `core/hashes.py` — hasher registry

- `ALGORITHMS: dict[name, Hasher]` where `Hasher = (name, digest(bytes)->bytes, hexlen, salted)`.
  Fast hashes via `hashlib` (md5, sha1, sha256, sha512); NTLM = `md4(utf-16le)`; MD4 via
  `core/md4.py`; SHA-512-crypt via stdlib `crypt` on POSIX, pure-Python fallback elsewhere.
- `make_byte_seed(index: int) -> bytes` — deterministic, domain-separated nonces used by
  `AttackEngine` to salt candidate generation per chunk (defends against lucky-offset
  collisions across runs). Mirrors `rng.hashes._Hash` shape expectations: anything with a
  `.digest(bytes) -> bytes` works, so attack code depends only on that interface
  (`HexTarget` adapter).
- **Semantics decision:** salted hashes in v1.0 are "salt known, crack like unsalted with
  prefix/suffix placement"; salt application order is `digest(salt + password)` for
  sha512-crypt-style records and configurable prefix/suffix for the fast hashes.

### 5.2 `core/md4.py` — RFC 1320, pure Python

Faithful reimplementation derived from the RFC's public-domain reference code:

- Constants: `0x5A827999` (√2), `0x6ED9EBA1` (√3); init `67452301 EFCDAB89 98BADCFE 10325476`.
- Little-endian throughout; padding to 448 mod 512 then 64-bit length.
- **Pinned test vectors (authoritative from RFC 1320 Appendix A.5):**
  - `MD4("")  = 31d6cfe0d16ae931b73c59d7e0c089c0`
  - `MD4("a") = bde52cb31de33e46245e05fbdbd6fb24`
  - `MD4("abc") = a448017aaf21d8525fc10ae87aa6729d`
  - `MD4("message digest") = d9130a8164549fe818874806e1c7014b`
  - `MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9`
  - `MD4("ABC...abc0123456789") = 043f8582f241db351ce627e153e7f0e4`
  - `MD4(80×"1234567890...") = e33b4ddc9c38f2199c3e7b164fcc0536`
- Rationale: NTLM needs MD4; `hashlib` dropped it on modern OpenSSL, so we ship our own
  and pin it with the RFC vectors so correctness is provable, not assumed.

### 5.3 `core/parser.py` — hash ingestion

- `HashRecord` dataclass: `raw, algo, digest_hex, salt, label, identified: bool, plaintext: str|None`.
- Accepted line formats (whitespace-tolerant, `#` comments, blank lines skipped):
  - `hash`
  - `hash:salt`
  - `hash:salt:label`
  - `label:::hash` family (loose split: last 32/40/64/128 hex token wins)
- `identify(hex_token)` — length + charset heuristics: 32→md5/md4/ntlm (all three tried),
  40→sha1, 64→sha256, 128→sha512, `$6$rounds=N$salt$...`→sha512-crypt.
- Registry keyed by `digest_hex.lower()`; duplicates merged; `plaintext_export()` for reports.

### 5.4 `core/wordlists.py` — wordlist provider

- Builtin assets ship inside the package; user dir configurable in Settings.
- Encoding policy: read as UTF-8 with `errors='replace'`; strip BOM; drop lines > 256 chars
  (defensive); dedupe via `set` with insertion-order preservation not required (throughput
  over aesthetics).
- `load_wordlist(path) -> list[str]` and `builtin_wordlists() -> list[(label, path)]`.

### 5.5 `core/rules.py` — hashcat-style rule engine

- Rule syntax subset (51 ops): `:` `l` `u` `c` `C` `t` `T` `d` `D n` `{` `}` `$x` `^x` `[` `]`
  `sXY` `@x` `*xy` `z n` `Z n` `q` `v` `.` `,` `y n` `Y n` `+` `-` `i n X` `o n X` `' n` `s` etc.
- Compiler turns each line into a list of closures; applied left-to-right like hashcat.
- Unknown op → rule line skipped (fail-closed with a logged warning, never a crash).
- `best64.rule` asset is a hand-written compatible subset (no licensing encumbrance).

### 5.6 `core/policy.py` — strength audit (NIST-aligned)

Checks per record (with plaintext known **or** unknown — audit works either way):
1. Length ≥ 8 (SP 800-63B minimum); recommend ≥ 15 for no-MSA accounts.
2. Not in top-common set (builtin weak list membership, case-insensitive).
3. Character-class diversity (lower/upper/digit/symbol) — scored, not hard-required
   (SP 800-63B explicitly *discourages* composition rules; we surface information,
   not enforcement).
4. No run-length > 3 (`aaaa`), no sequences ≥ 4 (`abcd`, `1234`), no keyboard walks
   (`qwerty`, `qaz`, `1qaz`).
5. Shannon entropy per char and estimated entropy bits (pattern-aware, not naive 6.5×len).
6. Verdict: `CRITICAL / WEAK / FAIR / STRONG` + actionable finding strings.

### 5.7 `core/attack.py` — AttackEngine

- Modes: `dictionary`, `rules` (wordlist × rule set), `mask`, `combinator` (wordlist1+wordlist2).
- Candidate generation is a generator; the worker thread pulls in chunks of 2,048.
- **Checkpointing:** every 250 ms the engine writes `{mode, position, counts, eta, rate}`
  to `session.json` in base_dir (atomic write via temp+rename).
- **Stop semantics:** `threading.Event`; checked per chunk; GUI can cancel < 300 ms.
- Candidate cap: mask mode hard-capped at 1,000,000 candidates (GUI shows the math before
  start; the operator confirms).
- ETA formula: `remaining / smoothed_rate` where `smoothed_rate = 0.7*instant + 0.3*prev`
  to avoid jitter.

### 5.8 `core/session.py` — SessionState

- Dataclass holding: loaded records snapshot, attack config, progress counters,
  per-record crack results, start/last-checkpoint timestamps.
- `to_dict()/from_dict()` for JSON persistence; `save(base_dir)` atomic; `load(base_dir)`.

### 5.9 `core/exporter.py` — reporting

- `export_html(path, records, meta)` — self-contained HTML (inline CSS, no CDN, no JS
  beyond a tiny sort helper inline), deterministic row order, embedded generation
  timestamp and tool version.
- `export_csv(path, records)` — proper quoting, CRLF for Excel friendliness.
- `export_json(path, records, meta)` — stable key order for diffability.

### 5.10 `core/selftest.py`

- Runs RFC 1320 vectors + registry round-trips + rule-engine golden cases + parser
  round-trips; returns `(ok: bool, report: str)`. GUI "Run Self-Test" button and CLI
  `python main.py --selftest` share this.

---

## 6. GUI Layer Design (Tkinter)

### 6.1 Threading model

- **Tk main thread:** all widget mutation. Worker never touches widgets.
- **Worker thread:** runs `AttackEngine`; publishes via `root.event_generate('<<WorkerTick>>')`
  (marshalled onto the Tk loop). Data handed over through a `queue.Queue`.
- **Guard:** second Start click is a no-op while a worker is alive; Stop sets the event and
  joins with timeout before re-enabling the button.

### 6.2 Screens (ttk.Notebook)

1. **Audit tab** — paste box + file/dir picker → parse → treeview (label, algo, verdict,
   findings, entropy) with per-row color coding; summary chips (`x critical · y weak · …`).
2. **Crack tab** — legal gate checkbox (disabled until checked), attack mode radio group,
   wordlist/rule pickers (builtin + file), mask editor with live candidate-count math,
   progress bar (smooth), rate + ETA + counts, live-found log, Stop button.
3. **Report tab** — export buttons + embedded HTML preview (Tkhtml-free fallback: plain
   text summary + "Open in browser" primary action; the HTML file itself is the artifact).
4. **Settings tab** — base_dir, wordlist dir, theme (dark/light), session save/load/clear,
   Run Self-Test, About.

### 6.3 Legal gate (hard requirement)

- `LegalBanner` component: red-bordered frame stating **authorized-own-hashes-only**.
- Start button stays `disabled` until: banner acknowledged **and** at least one hash loaded
  **and** a valid attack config present. No persistent "remember me" — consent is per-session.
- Every exported report stamps: *"Generated for hashes the operator owns/is authorized to test."*

### 6.4 Visual design

- Dark theme default (security-console aesthetic): `#0f1216` background, `#1a1f26` panels,
  `#3ddc84` accents for success, `#ff5370` for critical, monospace for hash/data columns.
- All colors hex→tk via one helper (`theme.py`); no scattered magic strings.
- HiDPI: fonts derived from `tkfont.nametofont('TkDefaultFont')` scaled, never hard-coded px.

---

## 7. Data Flow (crack run)

```
Load hashes ──▶ parser.identify ──▶ registry (dict by digest)
                                     │
Choose attack ──▶ AttackEngine(mode) │
   wordlist/rule/mask                ▼
 Worker thread: candidates ──▶ digest() ──▶ dict lookup O(1)
        │ found ──▶ record.plaintext=… ; log event ──▶ queue
        │ every 250 ms ──▶ checkpoint → session.json
        ▼
 <<WorkerTick>> on Tk loop ──▶ progress bar, rate, ETA, found-list refresh
        │ finished/cancelled
        ▼
 Exporter (HTML/CSV/JSON) ──▶ base_dir/reports/…   (user-invoked, explicit path)
```

---

## 8. Security Engineering of the Tool Itself

| Threat | Mitigation |
|---|---|
| Operator point-and-shoots at stolen dumps | Legal gate + per-session consent + audit-trail watermark in reports; no network so dumps must already be local |
| Tool used as library to bypass gate | Defense-in-depth not required for a GUI auditor (§1 stance), but gate is enforced in `AttackEngine.start()` too, not just the UI |
| Session/report files leak plaintexts | Written only into operator-owned base_dir; README documents risk; Settings offers "redact plaintexts in exports" toggle (default ON for HTML/CSV, JSON shows only lengths) |
| Builtin wordlists as attack ammo | Synthetic/educational only; documented in `assets/wordlists/README` — real breach corpora are deliberately NOT bundled |
| Tampered/unknown rule files | Rule compiler fail-closed per line; unknown ops skipped with warning |
| Path traversal via labels in reports | All report fields HTML-escaped (`html.escape`) before embedding |
| Denial of service via huge mask space | Hard cap 1M candidates + pre-start confirmation dialog showing the math |
| Crash leaves orphan worker | App exit joins worker with timeout; daemon thread as last resort |

---

## 9. Performance Envelope (expectations, stated honestly)

- Pure-Python `hashlib` cracking throughput target: **≈ 100–300 k cand/s** per core for
  MD5/SHA-1/NTLM on a modern laptop (chunked generator, precomputed dict of targets).
- SHA-512-crypt: intentionally slow (that's the point of the KDF); GUI warns and suggests
  limiting to the builtin weak list.
- Memory: wordlists are loaded fully; 100 M-line lists would need the (documented,
  out-of-scope) streaming redesign. Cap guidance shown in GUI for files > 200 MB.
- MD4 pure-Python: slower than hashlib; acceptable because NTLM targets are usually
  attacked via the same small candidate sets in audits.

---

## 10. Testing & Verification Strategy

| Layer | What | How |
|---|---|---|
| Unit | MD4 vs RFC 1320 vectors | `tests/test_core.py` (7 vectors, incl. 80-byte multi-block case) |
| Unit | Registry round-trip | hash→identify→match across all algos |
| Unit | Rule engine | golden input/output pairs per op + full best64 subset smoke |
| Unit | Parser | all accepted formats, comments, malformed lines, duplicates |
| Unit | Mask engine | candidate math (`?d?d?d?d`=10 000), cap enforcement |
| Unit | Policy | verdict boundaries (len 7/8, common, sequence, runs) |
| Unit | Session | save/load round-trip, atomicity on kill |
| GUI smoke | App boots, all tabs construct, self-test green | `python main.py --selftest` + manual |
| Packaging | EXE launches on clean Windows VM, no console flash | PyInstaller `--onefile --noconsole` + assets bundling |

Exit criteria for v1.0: full pytest suite green, self-test green inside the packaged EXE,
one E2E manual pass (load sample hashes → crack 3/5 with builtin list → export HTML).

---

## 11. Legal & Ethical Framework (non-negotiable)

1. **Own hashes only.** The tool is for auditing hashes you created or systems you own /
   are contractually authorized to test. Nothing else.
2. **Explicit consent gate** before any attack run (§6.3). No bypass, no persistence.
3. **No distribution of breach data.** Builtin wordlists are synthetic; the README and
   `assets/wordlists/README` say so plainly.
4. **No network.** The tool cannot exfiltrate anything even if misused; it only writes to
   the operator's chosen directory.
5. **Report watermarking** keeps derived artifacts inside the same authorization envelope.
6. Jurisdiction note in README: unauthorized access to computer systems is illegal nearly
   everywhere (e.g., CFAA in the US, Computer Misuse Act in the UK, Art. 7 GDPR duties for
   real user databases). The operator carries the legal responsibility; the tool enforces
   what it can and documents the rest.

---

## 12. Build & Packaging Plan

- **Dev run:** `python main.py` (Windows/macOS/Linux; tkinter required — it ships with
  python.org Windows builds).
- **Unit tests:** `python -m pytest tests/ -q` (or `python -m unittest` fallback via
  `tests/test_core.py` main shim).
- **Portable EXE:** PyInstaller `--onefile --noconsole --add-data assets` → single
  `HashArmor.exe`, no installer, no admin, runs from USB. Build scripts provided
  (`build_exe.ps1` / `build_exe.sh`). Requirements file pins `pyinstaller` for build only.
- **Anti-virus false positives:** documented in README (unsigned PyInstaller onefile
  binaries are commonly heuristically flagged; users can build their own from source).

---

## 13. Risks & Open Questions

| # | Risk | Mitigation / Status |
|---|---|---|
| R1 | MD4 correctness drift | RFC vectors pinned in unit tests — **closed** |
| R2 | `crypt` unavailable on Windows for sha512-crypt | Pure-Python fallback implemented — **closed** |
| R3 | Tk event marshalling race | Single queue + `event_generate` pattern; stop-join logic — **closed** |
| R4 | GIL limits throughput | Documented expectation (§9); `parallelism` hook for future — **accepted** |
| R5 | AV flags unsigned EXE | README guidance: build from source / add AV exclusion — **accepted** |
| R6 | User loads >200 MB wordlist in GUI | GUI warns above 200 MB and offers cancel — **planned** |
| R7 | Plaintext leakage via exports | Redaction toggle default ON (§8) — **closed** |

---

## 14. Milestones

- **M1 — Architecture freeze** (this document).
- **M2 — Core package** with pinned test vectors and unit suite green.
- **M3 — GUI four-tab app** with legal gate, live progress, sessions.
- **M4 — Reports + self-test + README/docs.**
- **M5 — Portable EXE build verified.**
