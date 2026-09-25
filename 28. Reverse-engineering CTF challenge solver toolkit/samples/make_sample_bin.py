#!/usr/bin/env python3
"""Generate samples/sample_challenge.bin — a tiny x86-64 ELF-style binary
with embedded flag material (base64, XOR, Caesar) for RECT self-testing.

Run:  python samples/make_sample_bin.py
"""

import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "sample_challenge.bin")

FLAG = "flag{r3v_1s_n0t_s0_h4rd}"

# Minimal ELF64 header (e_ident + rest) so the loader detects ELF.
ELF_HEADER = bytes.fromhex(
    "7f454c46020101000000000000000000"   # magic + class/data/version
    "02003e0001000000"                   # type=EXEC machine=x64 version
)


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def build() -> bytes:
    parts = []
    parts.append(ELF_HEADER)

    # fake section headers area
    parts.append(b"\x00" * 64)

    # strings table-ish content
    parts.append(b"\x00libc.so.6\x00printf\x00system\x00__isoc99_scanf\x00")
    parts.append(b"IsDebuggerPresent\x00")

    # plaintext hints
    parts.append(b"Enter the magic word: \x00")
    parts.append(b"Correct!\x00Wrong key.\x00")

    # the flag, base64-encoded, line-wrapped so classify_string sees it
    b64 = base64.b64encode(FLAG.encode()).decode()
    parts.append(b"B64:" + b64.encode() + b"\x00")

    # the flag, single-byte XOR with 0x42
    parts.append(b"XOR:" + xor_bytes(FLAG.encode(), 0x42) + b"\x00")

    # the flag, rot13-style Caesar (+13 on letters)
    rot = []
    for ch in FLAG:
        if "a" <= ch <= "z":
            rot.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            rot.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            rot.append(ch)
    parts.append(b"ROT:" + "".join(rot).encode() + b"\x00")

    # filler code bytes so disasm/entropy have material
    parts.append(bytes.fromhex(
        "554889e54883ec10c745fc000000008b45fc83f80a740583f8147505"
        "bf01000000e9c00000005be95affffffc9c3"))
    return b"".join(parts)


def main() -> int:
    data = build()
    with open(OUT, "wb") as fh:
        fh.write(data)
    print(f"wrote {OUT} ({len(data)} bytes)")
    print(f"embedded flag: {FLAG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
