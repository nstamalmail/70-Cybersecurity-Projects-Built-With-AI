"""Shared self-test used by both the GUI and `python main.py --selftest`."""

from __future__ import annotations

import os
import tempfile
from typing import List, Tuple

from . import md4 as md4mod
from . import rules as rule_mod
from .attack import AttackEngine, LegalGateRequired
from .exporter import export_csv, export_html, export_json
from .hashes import ALGORITHMS
from .parser import HashRecord, parse_line, parse_text
from .policy import audit_plaintext
from .session import AttackConfig, SessionState


def _check(name: str, ok: bool, problems: List[str]) -> None:
    if not ok:
        problems.append(name)


def _group(lines: List[str], problems: List[str], start: int, label: str) -> None:
    """Record PASS/FAIL for one group based on problems added since *start*."""
    failed = len(problems) - start
    lines.append(f"{label}: {'PASS' if failed == 0 else 'FAIL'}")


def run_selftest() -> Tuple[bool, str]:
    problems: List[str] = []
    lines: List[str] = []

    # 1. RFC 1320 MD4 vectors (authoritative, Appendix A.5)
    vectors = {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
        b"a": "bde52cb31de33e46245e05fbdbd6fb24",
        b"abc": "a448017aaf21d8525fc10ae87aa6729d",
        b"message digest": "d9130a8164549fe818874806e1c7014b",
        b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
            "043f8582f241db351ce627e153e7f0e4",
        b"1234567890" * 8: "e33b4ddc9c38f2199c3e7b164fcc0536",
    }
    g0 = len(problems)
    for data, want in vectors.items():
        got = md4mod.md4_hex(data)
        _check(f"md4({data[:20]!r}) == {want}", got == want, problems)
    _group(lines, problems, g0, "[1] MD4 RFC 1320 vectors")

    # 2. Registry round-trips
    for name in ("md5", "sha1", "sha256", "sha512"):
        h = ALGORITHMS[name]
        import hashlib
        want = getattr(hashlib, name)(b"test").hexdigest()
        _check(f"{name} round-trip", h.digest(b"test").hex() == want, problems)
    _check("ntlm", ALGORITHMS["ntlm"].digest(b"abc").hex()
           == md4mod.md4_hex("abc".encode("utf-16le")), problems)
    _group(lines, problems, g0, "[2] Hasher registry")

    # 3. Parser formats
    cases = {
        "5f4dcc3b5aa765d61d8327deb882cf99": 32,
        "5f4dcc3b5aa765d61d8327deb882cf99:mysalt": 32,
        "5f4dcc3b5aa765d61d8327deb882cf99:mysalt:admin": 32,
        "admin::5f4dcc3b5aa765d61d8327deb882cf99": 32,
        "7c4a8d09ca3762af61e59520943dc26494f8941b": 40,
        "# comment": 0,
        "": 0,
    }
    g0 = len(problems)
    for raw, want_len in cases.items():
        rec = parse_line(raw)
        got = rec.digest_hex.__len__() if rec else 0
        _check(f"parse '{raw[:30]}' -> len {want_len}", got == want_len, problems)
    _group(lines, problems, g0, "[3] Parser formats")

    # 4. Rule engine golden cases
    def one(rule: str, word: str) -> str:
        ops, probs = rule_mod.compile_rule(rule)
        return rule_mod.apply_rule(word, ops)
    _check("rule lowercase", one("l", "ABC") == "abc", problems)
    _check("rule append !", one("$!", "abc") == "abc!", problems)
    _check("rule prepend 1", one("^1", "abc") == "1abc", problems)
    _check("rule capitalize", one("c", "abc") == "Abc", problems)
    _check("rule duplicate", one("d", "abc") == "abcabc", problems)
    _check("rule sXY", one("s@a", "ab@") == "aba", problems)
    _check("rule reject-if-contains", one("*ac", "abc") == "", problems)
    _check("rule reject-passes", one("*xz", "abc") == "abc", problems)
    _check("rule truncate", one("'2", "abcdef") == "ab", problems)
    bad_ops, bad_probs = rule_mod.compile_rule("Ω")
    _check("unknown rule op fails closed", bad_ops == [] and len(bad_probs) == 1,
           problems)
    _group(lines, problems, g0, "[4] Rule engine")

    # 5. Policy audit verdict boundaries
    g0 = len(problems)
    v, _, _ = audit_plaintext("password")          # common + short
    _check("audit 'password' CRITICAL", v == "CRITICAL", problems)
    v, _, _ = audit_plaintext("Str0ng&Unique#Passphrase!2026")
    _check("audit strong stays STRONG", v == "STRONG", problems)
    v, _, _ = audit_plaintext("abcd1234")           # sequence
    _check("audit 'abcd1234' not STRONG", v in ("WEAK", "CRITICAL", "FAIR"), problems)
    _group(lines, problems, g0, "[5] Policy audit")

    # 6. Mask math + gate enforcement
    recs = parse_text(
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        "7c4a8d09ca3762af61e59520943dc26494f8941b:123456\n")
    eng = AttackEngine(recs, AttackConfig(mode="dictionary"))
    g0 = len(problems)
    try:
        eng.run()
        _check("gate blocks unauthorized run", False, problems)
    except LegalGateRequired:
        pass
    _group(lines, problems, g0, "[6] Legal gate enforcement")

    # 7. End-to-end dictionary run (authorized) + session round-trip
    wordfile = os.path.join(tempfile.gettempdir(), "hasharmor_selftest_words.txt")
    with open(wordfile, "w", encoding="utf-8") as fh:
        fh.write("password\n123456\nletmein\n")
    g0 = len(problems)
    eng = AttackEngine(recs, AttackConfig(mode="dictionary", wordlist=wordfile),
                       authorized=True)
    result = eng.run()
    _check("e2e found 2", result["found"] == 2, problems)
    st = SessionState(records=recs, config=eng.config)
    st.cracked = {r.digest_hex: r.plaintext for r in recs if r.plaintext}
    tmpdir = tempfile.mkdtemp(prefix="hasharmor_")
    st.save(tmpdir)
    st2 = SessionState.load(tmpdir)
    _check("session round-trip", st2 is not None and len(st2.records) == len(recs),
           problems)
    _check("session cracked preserved", st2 and st2.cracked.get(
        "5f4dcc3b5aa765d61d8327deb882cf99") == "password", problems)
    _group(lines, problems, g0, "[7] E2E run + session")

    # 8. Exports produce files
    hp = export_html(os.path.join(tmpdir, "r.html"), recs)
    cp = export_csv(os.path.join(tmpdir, "r.csv"), recs)
    jp = export_json(os.path.join(tmpdir, "r.json"), recs)
    g0 = len(problems)
    _check("exports", all(os.path.isfile(p) for p in (hp, cp, jp)), problems)
    _group(lines, problems, g0, "[8] Report exports")

    ok = not problems
    report = "\n".join(lines) + f"\n\nOverall: {'ALL PASS' if ok else 'FAILURES'}"
    if problems:
        report += "\n" + "\n".join(f"  - {p}" for p in problems)
    return ok, report


if __name__ == "__main__":
    ok, rep = run_selftest()
    print(rep)
    raise SystemExit(0 if ok else 1)
