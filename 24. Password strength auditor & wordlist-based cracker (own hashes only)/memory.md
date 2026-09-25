# memory.md — HashArmor durable memory

> Purpose: cross-session memory that should survive any context loss. Lessons, pitfalls,
> conventions, and ethical constraints for this project. **Read this file before resuming
> any work on HashArmor.**

---

## 1. Project identity (never forget)

- **Name:** HashArmor — defensive password strength auditor & wordlist-based cracker.
- **Hard scope rule:** the operator may attack **only hashes they own or are authorized
  to test**. The legal gate is a core feature, not decoration. Never weaken it, never
  add a bypass, never persist consent across sessions.
- **Runtime deps:** Python standard library ONLY. `pyinstaller` is a build-time dep
  (requirements.txt) and must never be imported by project code.
- **Offline-only:** no network calls, no telemetry, no auto-update — ever.

## 2. Ethics constraints (non-negotiable)

1. Never bundle real breach corpora (rockyou etc.). Builtin lists are synthetic.
2. Reports and exports must carry the authorization watermark.
3. Plaintext redaction in exports defaults ON.
4. If a future request conflicts with §1/§2, the request is declined and this file is cited.

## 3. Environment facts (Windows host)

- Shell is **bash** (Git Bash): use `ls`, forward slashes; never `dir`, `del`, backslashes.
- Python 3.12.7 at `python`; tkinter OK; pip 26.2.1.
- Tool-call convention learned here: `write_file` requires the `instructions` field —
  omitting it errors out (hit twice; do not repeat).

## 4. Technical pitfalls to remember

| Pitfall | Rule |
|---|---|
| `hashlib.md4` missing on modern OpenSSL/Windows | Use `core/md4.py`; vectors are in tests — do not "simplify" them away |
| NTLM ≠ MD5 | NTLM = `md4(pw.encode('utf-16le'))` |
| `crypt` module does not exist on Windows | sha512-crypt uses stdlib crypt on POSIX, documented fallback elsewhere |
| Tk is single-threaded | Worker threads must NEVER touch widgets; use `queue.Queue` + `root.event_generate` |
| Tk widgets must exist before use | Build BOTH comboboxes before filling them (hit: `_reload_builtins` before `wl2_combo` existed) |
| MD4 body must mask with `& 0xFFFFFFFF` | Python ints are unbounded; C semantics required |
| Rule engine unknown ops | Fail-closed per line: skip + warn; never raise mid-run. hashcat `$x` chars may be ANY char incl. digits (`$1`), and multi-char sequences like `sso0` are INVALID (one op per token) |
| sha512-crypt digests are NOT hex | They use the crypt base64 alphabet `./0-9A-Za-z`, 86 chars — regex must match that |
| Mask expansion explodes | Keep the 1,000,000-candidate cap; show the math before start |
| Early-exit when all targets crack | Don't burn the remaining keyspace after the last find (mask test took 60 s without this) |
| Atomic writes | temp file + `os.replace` for session.json; never write in place |
| PyInstaller assets | Use `sys._MEIPASS`-aware resource path helper (`core/wordlists._resource_root`); `--add-data` for assets/ |
| Unsigned onefile EXE | Expect AV false positives; document "build from source" guidance in README |
| write_file tool | ALWAYS include the `instructions` field — omitting it hard-errors (hit 3×; do not repeat) |

## 5. Conventions

- Tabs: 4 spaces; type hints on public functions; docstrings on modules.
- Colors/strings centralized in `gui/theme.py`; no magic literals in tab files.
- Reports deterministic: fixed row order, stable key order in JSON.
- Tests are the spec: if a behavior changes, its golden test changes in the same commit.
- Docs live at repo root: `architecture.md`, `state.md`, `memory.md` (update `state.md`
  after every meaningful change).

## 6. Resume checklist (in order)

1. Read `state.md` → current phase + component table.
2. `python main.py --selftest` — must be green before anything else.
3. `python -m pytest tests/ -q` — must be green.
4. Check §4 pitfalls before touching md4/rules/threading/packaging.
5. After finishing work: update `state.md` ledger + next actions.

## 7. Glossary (shared vocabulary)

- **Record** — one parsed hash line (`HashRecord`).
- **Registry** — dict of digest_hex → records for O(1) crack lookups.
- **Gate** — the legal acknowledgment controlling Start (§1 of this file).
- **Checkpoint** — 250 ms attack-state snapshot written atomically to session.json.
- **base_dir** — the only directory HashArmor writes to (sessions/, reports/).
