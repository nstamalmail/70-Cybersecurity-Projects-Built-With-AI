# RECT sample data

Manual input files you can load into the GUI instead of (or alongside) your
own challenge binaries.

| File | What it is | Where to load it |
|---|---|---|
| `sample_challenge.bin` | Tiny x86-64-style binary with the flag hidden in base64 / XOR / Caesar layers. | Workspace → **Load sample challenge file…** (or Browse) |
| `make_sample_bin.py` | Regenerates `sample_challenge.bin`. | `python samples/make_sample_bin.py` |
| `sample_encrypted_text.txt` | Ready-made encoded strings (base64/hex/url/rot13/Caesar/Vigenère/XOR) with solutions. | Copy a line → Crypto helpers → Input → Run |
| `sample_writeup_data.json` | What a finished case looks like; also usable as a writeup-export reference. | Reference / Writeup tab export |

## Quick start with the sample binary

1. Start RECT → **1. Workspace**
2. Name the challenge, then **⬆ Load sample challenge file…** → pick
   `samples/sample_challenge.bin`
3. Watch **2. Analysis** (strings/entropy) and the console — the flag-like
   string is auto-flagged
4. **3. Crypto helpers** → op `decode`, encoding `base64`, paste the `B64:`
   content → Run → flag appears in output
5. **5. Writeup** → enter the flag, mark solved, **Export writeup…** to
   Markdown/HTML/JSON/CSV anywhere

## Report/writeup generation without solving anything

Use **5. Writeup → Export** at any time: the writeup assembles the case
metadata, the replayable operation log, your notes and the flag into
downloadable files in the folder you choose.

All sample files are plain text/binary and meant to be edited.
