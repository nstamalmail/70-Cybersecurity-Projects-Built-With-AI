# HashArmor

**Offline password strength auditor & wordlist-based cracker — for hashes YOU own.**

A portable, single-file GUI tool (Windows EXE / cross-platform Python) that parses
password hashes, audits them against NIST SP 800-63B guidance, and demonstrates their
weakness with wordlist / rules / mask / combinator attacks against **your own** hashes.

> ⚠️ **Legal**: only load hashes you created or systems you own / are contractually
> authorized to test. The app enforces an authorization gate on every attack run.

---

## Quick start (from source)

```bash
python main.py              # GUI
python main.py --selftest   # core self-tests (RFC 1320 vectors, E2E crack, exports)
python -m pytest tests/ -q  # full unit suite
```

Requirements: Python 3.10+ with tkinter (standard on python.org Windows builds).
**Runtime = standard library only.**

## Portable EXE

```bash
build_exe.bat   # Windows  -> dist\HashArmor.exe
./build_exe.sh  # Linux/macOS -> dist/HashArmor
```

One file, no installer, no admin rights, runs from USB. AV note: unsigned
PyInstaller onefile binaries are sometimes heuristically flagged — build from
source yourself if your AV objects.

## Features

| Area | What you get |
|---|---|
| Ingest | Paste / file / directory of `hash`, `hash:salt`, `hash:salt:label`, `label::hash` lines |
| Identify | MD5, SHA-1, SHA-256, SHA-512, NTLM, MD4, SHA-512-crypt (`$6$rounds=...`) |
| Attacks | Wordlist · Wordlist+Rules (best64-compatible) · Mask (capped 1M, live math) · Combinator |
| Audit | NIST-aligned verdicts (CRITICAL/WEAK/FAIR/STRONG), Shannon entropy, sequences, walks, runs |
| Sessions | Checkpoint saves to `<workspace>/sessions/session.json` (atomic writes) |
| Reports | Self-contained HTML + CSV + JSON with authorization watermark |

## Docs

- `architecture.md` — full system design (senior-security review)
- `state.md` — live build state & verification ledger
- `memory.md` — durable constraints & pitfalls (read before contributing)
