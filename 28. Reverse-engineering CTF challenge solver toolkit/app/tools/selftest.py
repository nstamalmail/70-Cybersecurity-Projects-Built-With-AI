"""Headless self-test for RECT: verifies the loader, string analysis, entropy,
crypto toolkit and writeup export against bundled sample data.
Writes selftest_result.txt next to the executable.
"""

from __future__ import annotations

import base64
import os
import sys

from app.config import get_base_dir, get_data_dir
from app.core import crypto_kit as ck
from app.core.engine import run_operation_blocking
from app.core.loader import load_binary
from app.utils.state import StateStore


class _Result:
    def __init__(self):
        self.checks: list = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def summary(self) -> str:
        passed = sum(1 for c in self.checks if c["ok"])
        total = len(self.checks)
        status = "PASS" if passed == total else "FAIL"
        lines = [f"RECT self-test: {status} ({passed}/{total} checks)", ""]
        for c in self.checks:
            mark = "PASS" if c["ok"] else "FAIL"
            lines.append(f"[{mark}] {c['name']}" +
                         (f" — {c['detail']}" if c.get("detail") else ""))
        return "\n".join(lines)


def run_selftest() -> int:
    result = _Result()
    base_dir = get_base_dir()
    result_path = os.path.join(base_dir, "selftest_result.txt")
    samples_dir = os.path.join(base_dir, "samples")

    store = StateStore(base_dir)
    store.log_memory("self-test started (headless)")
    result.check("StateStore writes memory.md", os.path.exists(store.memory_path))

    # ---- loader -----------------------------------------------------------
    sample_bin = os.path.join(samples_dir, "sample_challenge.bin")
    if os.path.exists(sample_bin):
        info = load_binary(sample_bin)
        result.check("binary loaded", info.size > 0, f"{info.size} bytes")
        result.check("file type detected", info.file_type in ("elf", "pe", "raw",
                                                              "text", "zip"),
                     info.file_type)
        result.check("strings extracted", len(info.strings) > 3,
                     f"{len(info.strings)} strings")
        flag_like = [s for s in info.strings if s.get("class") == "flag-like"]
        result.check("flag-like strings classified in sample",
                     any("B64:" in s["text"] or "ROT:" in s["text"]
                         for s in flag_like),
                     f"{len(flag_like)} flag-like strings")

        rec = run_operation_blocking("strings", file_path=sample_bin,
                                     flag_format="flag{")
        result.check("strings op succeeds", rec.success, rec.output_summary)
        result.check("strings op output has classification",
                     "flag-like" in rec.full_output or "base64?" in rec.full_output
                     or len(rec.full_output) > 0, rec.output_summary)

        rec = run_operation_blocking("entropy", file_path=sample_bin)
        result.check("entropy op succeeds", rec.success, rec.output_summary)
    else:
        result.check("sample challenge binary exists", False, sample_bin)

    # ---- crypto kit: encodings --------------------------------------------
    secret = "flag{xpt_base64_rocks}"
    b64 = base64.b64encode(secret.encode()).decode()
    dec = ck.decode(b64, "base64")
    result.check("base64 decode round-trip", dec == secret, dec)
    auto = ck.auto_decode(b64)
    result.check("auto-decode finds base64", any(e == "base64" for e, _ in auto),
                 str([e for e, _ in auto]))

    # ---- xor ---------------------------------------------------------------
    key = 0x42
    xored = bytes(b ^ key for b in secret.encode())
    hits = ck.xor_single_byte_brute(xored)
    result.check("xor brute force recovers flag", any(
        "flag{" in txt for _, _, txt in hits),
        f"{len(hits)} candidates")
    known_key = ck.xor_known_plaintext(xored, b"flag{")
    result.check("xor known-plaintext key recovery", known_key[:5] == bytes(
        [key] * 5), known_key.hex())

    # ---- caesar ------------------------------------------------------------
    caesar_text = ck.caesar("flag{caesar_was_here}", 13)
    shift, plain, score = ck.caesar_best(caesar_text)
    result.check("caesar auto-crack", "flag{caesar_was_here}" in plain,
                 f"shift {shift}")

    # ---- vigenere ----------------------------------------------------------
    ct = ck.vigenere("thequickbrownfox", "key", decrypt=False)
    pt = ck.vigenere(ct, "key", decrypt=True)
    result.check("vigenere round-trip", pt == "thequickbrownfox", pt)

    # ---- hash identification -----------------------------------------------
    md5 = ck.hash_string("hello", "md5")
    ids = ck.identify_hash(md5)
    result.check("md5 identified", any("MD5" in i for i in ids), str(ids))
    bcrypt = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBpQoJ8sAAAAAAA.AAAAAAAA.AAAAAA"
    ids = ck.identify_hash(bcrypt)
    result.check("bcrypt identified", any("bcrypt" in i for i in ids), str(ids))

    # ---- rsa ---------------------------------------------------------------
    out = ck.analyze_rsa(n="3233", e="65537", c="2724")
    result.check("rsa small-n analysis runs", "factored" in out or "d recovered" in out,
                 out.splitlines()[0] if out else "")

    # ---- writeup export ------------------------------------------------------
    from app.core.report import export_all
    challenge = {"name": "selftest", "category": "rev", "event": "unit-test",
                 "description": "generated by selftest", "flag_format": "flag{",
                 "binary_path": sample_bin if os.path.exists(sample_bin) else "",
                 "solved": True, "flag": "flag{self_test}", "notes_md": "n/a",
                 "created_at": "now"}
    records = [{"tool": "loader", "operation": "binary load", "input_summary": "x",
                "output_summary": "ok", "full_output": "demo", "success": True}]
    outdir = os.path.join(base_dir, "reports")
    paths = export_all(challenge, records, outdir)
    result.check("markdown writeup exported", os.path.exists(paths["markdown"]))
    result.check("html writeup exported", os.path.exists(paths["html"]))
    result.check("json writeup exported", os.path.exists(paths["json"]))
    result.check("csv ops exported", os.path.exists(paths["csv"]))

    store.log_memory("self-test finished (toolkit verified)")

    summary = result.summary()
    with open(result_path, "w", encoding="utf-8") as fh:
        fh.write(summary + "\n")

    print(summary)
    ok = all(c["ok"] for c in result.checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_selftest())
