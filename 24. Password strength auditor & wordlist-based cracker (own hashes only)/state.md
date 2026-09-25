# state.md — HashArmor live build state

> Purpose: single source of truth for *where the build is right now* — decisions taken,
> verification performed, and what remains. Update this file after every meaningful change.

- **Last updated:** 2026-09-08
- **Current phase:** M5 — Packaging (EXE build)
- **Overall progress:** M1–M4 complete (architecture, core, GUI, docs/tests); 31/31 unit tests + 8/8 self-test groups green; GUI E2E verified (parse → audit → crack 3/3 → session save)

---

## 1. Environment snapshot

| Item | Value |
|---|---|
| OS | Windows, bash shell (Git Bash); use POSIX syntax, forward-slash paths |
| Python | 3.12.7 (`python` on PATH) |
| tkinter | Present and importable ✔ |
| pip | 26.2.1 |
| Project dir | empty at session start — greenfield build |
| Build deps | `pyinstaller` via requirements.txt (build-time only; runtime = stdlib) |

## 2. Architecture decisions (frozen — see architecture.md for detail)

| # | Decision | Rationale |
|---|---|---|
| D1 | Std-lib only at runtime | Portability, tiny EXE, no supply-chain surface; hashcat/MD4 semantics reimplemented + pinned by tests |
| D2 | Tkinter GUI (not PySide/webview) | Ships with python.org Windows Python → smallest friction for portable EXE |
| D3 | Pure-Python MD4 per RFC 1320 | hashlib dropped md4 on modern OpenSSL; NTLM requires MD4 |
| D4 | Single worker thread + `event_generate` | Keep GUI responsive; multiprocessing overkill under GIL; hook left for future |
| D5 | Legal gate enforced in engine, not just UI | Defense against casual misuse; see architecture §8/§11 |
| D6 | Reports HTML/CSV/JSON, self-contained HTML | Deterministic, offline-viewable, no CDN |
| D7 | Builtin wordlists synthetic only | No breach-data distribution; ethics stance |
| D8 | Mask cap 1,000,000 candidates + confirm dialog | DoS/foot-gun guard |

## 3. RFC 1320 verification note

MD4 test vectors were checked against the authoritative RFC 1320 text (rfc-editor.org)
during architecture phase — Appendix A.5 vectors pinned in `tests/test_core.py`:

```
MD4("")                                 = 31d6cfe0d16ae931b73c59d7e0c089c0
MD4("a")                                = bde52cb31de33e46245e05fbdbd6fb24
MD4("abc")                              = a448017aaf21d8525fc10ae87aa6729d
MD4("message digest")                   = d9130a8164549fe818874806e1c7014b
MD4("abcdefghijklmnopqrstuvwxyz")       = d79e1c308aa5bbcdeea8ed63df412da9
MD4("ABCdef…0123456789" 62-char)        = 043f8582f241db351ce627e153e7f0e4
MD4(80-char "1234567890…" repeat)       = e33b4ddc9c38f2199c3e7b164fcc0536
```

## 4. Component status

| Component | State | Notes |
|---|---|---|
| architecture.md | ✔ done | Frozen for v1.0 |
| state.md | ✔ done | This file |
| memory.md | ✔ done | Durable lessons/pitfalls |
| core/md4.py | ✔ done | RFC 1320, 7 pinned vectors pass |
| core/hashes.py | ✔ done | registry, NTLM, sha512-crypt (Windows falls back honestly) |
| core/parser.py | ✔ done | all formats per §5.3; sha512-crypt regex uses crypt-base64 alphabet |
| core/wordlists.py | ✔ done | builtin discovery + external, dedupe/256-char cap |
| core/rules.py | ✔ done | 50+ ops incl. r/f; single-char `*x` supported; fail-closed |
| core/policy.py | ✔ done | NIST-aligned verdicts + entropy + patterns |
| core/attack.py | ✔ done | 4 modes; algo confirmed on crack; early-exit when all cracked |
| core/session.py | ✔ done | atomic save/load + clear_session_file() |
| core/exporter.py | ✔ done | HTML/CSV/JSON, watermark, escaped |
| core/selftest.py | ✔ done | 8 groups, per-group PASS/FAIL |
| assets/wordlists/ | ✔ done | synthetic lists + 110-line best64 subset (all lines compile) |
| gui/theme.py, components.py | ✔ done | dark palette, SmoothProgress, LegalBanner |
| gui/tabs/* | ✔ done | audit, crack, report, settings |
| gui/app.py | ✔ done | Notebook + thread-safe post() queue |
| main.py + CLI | ✔ done | --selftest verified |
| tests/test_core.py | ✔ done | 31 tests green |
| PyInstaller EXE | ✔ done | dist/HashArmor.exe (10.5 MB, onefile --windowed), launched & verified |

## 5. Verification ledger

| Date | Check | Result |
|---|---|---|
| 2026-09-08 | Python/tkinter/pip availability | ✔ confirmed |
| 2026-09-08 | RFC 1320 vectors sourced from rfc-editor.org | ✔ confirmed |
| 2026-09-08 | `python main.py --selftest` | ✔ 8/8 groups ALL PASS |
| 2026-09-08 | pytest suite | ✔ 31/31 passed |
| 2026-09-08 | GUI boots, 4 tabs render | ✔ smoke-tested headless with after() driver |
| 2026-09-08 | E2E: demo hashes → audit → crack 3/3 (password/123456/letmein) → verdicts CRITICAL → session saved | ✔ |
| 2026-09-08 | py_compile across all sources | ✔ |
| 2026-09-08 | EXE build (PyInstaller 6.22.2, onefile, windowed) | ✔ dist/HashArmor.exe |
| 2026-09-08 | EXE launch + bundled asset extraction (_MEIPASS/assets/wordlists) | ✔ verified |
| — | EXE on a clean Windows VM | manual step for the operator (same-machine launch verified) |

## 6. Next actions

1. ✅ ~~Implement core package~~ — done.
2. ✅ ~~Assets + tests~~ — 31/31 green.
3. ✅ ~~GUI layer~~ — boots + E2E verified.
4. ✅ ~~PyInstaller EXE~~ — dist/HashArmor.exe verified.
5. Optional v1.1 candidates: ProcessPoolExecutor scale-out via `AttackEngine.parallelism` hook, plaintext-redaction toggle in exports (architecture §8), >200 MB wordlist streaming warning (architecture R6).
