# RECT — Reverse-Engineering CTF Solver Toolkit

One workspace per CTF challenge: binary analysis, strings/entropy, a
crypto/encoding helper panel, a replayable operation log, and one-click
writeup export. Pure-stdlib core — no Ghidra/r2/angr required (capstone is an
optional accelerator for the disassembly pane).

## Run from source

```
pip install -r requirements.txt
python main.py
```

Optional disassembly:

```
pip install capstone
```

## Run the portable exe

Copy `dist/RECT.exe` anywhere and double-click.

## Workflow

1. **1. Workspace** — challenge name/category/event/flag-format + file.
   **⬆ Load sample challenge file…** for `samples/sample_challenge.bin`.
2. **2. Analysis** — strings (auto-classified: base64?, flag-like,
   format-string, anti-debug?…), hex view, entropy map, optional disassembly.
3. **3. Crypto helpers** — decode/encode (auto-detect, base64/32/16, hex,
   url, rot13), XOR (key / single-byte brute force / known-plaintext), hash
   identification (MD5..SHA-512, bcrypt, sha512crypt, Argon2…), Caesar
   (auto best-shift), Vigenère, small-RSA solver.
4. **4. Ops & console** — every operation is recorded with full output; the
   flag-format field auto-spots flags in any output.
5. **5. Writeup** — notes, flag, solved status; **Export writeup…** produces
   Markdown + HTML + JSON + CSV into any folder.
6. **6. History** — saved challenges from SQLite; reopen any case with its
   full operation log.

## Sample data (samples/)

| File | Purpose |
|---|---|
| `sample_challenge.bin` | Tiny ELF-style binary with the flag in base64 / XOR(0x42) / rot13 layers |
| `make_sample_bin.py` | Regenerates the sample binary |
| `sample_encrypted_text.txt` | Ready-made decode exercises with solutions |
| `sample_writeup_data.json` | Reference for a finished case + operation log |

## Self-test

```
python main.py --selftest      # 21 checks: loader, strings, entropy, crypto, writeup
```

## Files

- `state.md` — live snapshot maintained by the app
- `memory.md` — append-only session/challenge history
