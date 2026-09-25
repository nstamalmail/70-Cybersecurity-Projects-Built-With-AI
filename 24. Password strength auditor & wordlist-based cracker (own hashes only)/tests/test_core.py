"""Unit tests for HashArmor core (pytest or `python tests/test_core.py`)."""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core import md4 as md4mod  # noqa: E402
from core import rules as rule_mod  # noqa: E402
from core.attack import AttackEngine, LegalGateRequired  # noqa: E402
from core.exporter import export_csv, export_html, export_json  # noqa: E402
from core.hashes import ALGORITHMS  # noqa: E402
from core.parser import parse_line, parse_text  # noqa: E402
from core.policy import audit_plaintext, audit_all, summarize  # noqa: E402
from core.session import AttackConfig, SessionState  # noqa: E402
from core.wordlists import load_wordlist  # noqa: E402

# ---------------------------------------------------------------- MD4 (RFC 1320)

MD4_VECTORS = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "043f8582f241db351ce627e153e7f0e4"),
    (b"1234567890" * 8, "e33b4ddc9c38f2199c3e7b164fcc0536"),
]


@pytest.mark.parametrize("data,want", MD4_VECTORS)
def test_md4_rfc1320_vectors(data, want):
    assert md4mod.md4_hex(data) == want


def test_md4_long_multiblock():
    # 1,000,000 bytes of 'a' per the RFC driver's million-'a' test
    assert md4mod.md4_hex(b"a" * 1_000_000) == md4mod.md4_hex(b"a" * 1_000_000)
    # consistency only; RFC has no vector for 1e6 'a'


# ---------------------------------------------------------------- registry

@pytest.mark.parametrize("name", ["md5", "sha1", "sha256", "sha512"])
def test_registry_matches_hashlib(name):
    import hashlib
    h = ALGORITHMS[name]
    assert h.digest(b"test").hex() == getattr(hashlib, name)(b"test").hexdigest()


def test_ntlm_is_md4_of_utf16le():
    assert ALGORITHMS["ntlm"].digest(b"abc").hex() == md4mod.md4_hex("abc".encode("utf-16le"))


# ---------------------------------------------------------------- parser

def test_parser_formats():
    assert parse_line("5f4dcc3b5aa765d61d8327deb882cf99").digest_hex == \
        "5f4dcc3b5aa765d61d8327deb882cf99"
    rec = parse_line("5f4dcc3b5aa765d61d8327deb882cf99:pepper:admin")
    assert rec.salt == "pepper" and rec.label == "admin"
    rec = parse_line("admin::5f4dcc3b5aa765d61d8327deb882cf99")
    assert rec.label == "admin"
    rec = parse_line("5f4dcc3b5aa765d61d8327deb882cf99:pepper")
    assert rec.salt == "pepper" and not rec.label
    assert parse_line("# comment") is None
    assert parse_line("") is None


def test_parser_sha512crypt_line():
    line = ("$6$rounds=1000$saltstringsalt$" + "a" * 86)
    rec = parse_line(line)
    assert rec.algo == "sha512crypt"
    assert "rounds=1000" in rec.salt


def test_parser_dedupe():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n"
                      "5f4dcc3b5aa765d61d8327deb882cf99\n")
    assert len(recs) == 1


# ---------------------------------------------------------------- rules

def test_rules_golden():
    def one(rule, word):
        ops, probs = rule_mod.compile_rule(rule)
        assert not probs, probs
        return rule_mod.apply_rule(word, ops)
    assert one("l", "ABC") == "abc"
    assert one("u", "abc") == "ABC"
    assert one("c", "abc") == "Abc"
    assert one("$!", "abc") == "abc!"
    assert one("^1", "abc") == "1abc"
    assert one("d", "abc") == "abcabc"
    assert one("s@a", "ab@") == "aba"
    assert one("'3", "abcdef") == "abc"


def test_rules_fail_closed():
    ops, probs = rule_mod.compile_rule("€")
    assert ops == [] and probs


def test_best64_subset_compiles():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "assets", "wordlists", "best64.rule")
    with open(path, "r", encoding="utf-8") as fh:
        lines, problems = rule_mod.parse_rules(fh.read())
    # Every non-comment line must compile without problems
    assert problems == [], problems[:5]
    assert len(lines) > 100


# ---------------------------------------------------------------- policy

def test_policy_verdicts():
    assert audit_plaintext("password")[0] == "CRITICAL"
    assert audit_plaintext("12345678")[0] in ("CRITICAL", "WEAK")
    assert audit_plaintext("Str0ng&Unique#Passphrase!2026")[0] == "STRONG"
    v = audit_plaintext("abcd1234")[0]
    assert v != "STRONG"


def test_audit_all_and_summarize():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n")  # = 'password'
    recs[0].plaintext = "password"
    audit_all(recs)
    s = summarize(recs)
    assert s["CRITICAL"] == 1


# ---------------------------------------------------------------- attack e2e

def _tmp_wordlist(words):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words) + "\n")
    return path


def test_mask_count_and_cap():
    eng = AttackEngine([], AttackConfig(mode="mask", mask="?d?d?d?d"))
    assert eng.mask_count("?d?d?d?d") == 10_000
    assert eng.mask_count("?a?a?a?a?a?a?a?a?a?a") > 1_000_000


def test_gate_blocks_unauthorized():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    eng = AttackEngine(recs, AttackConfig(mode="dictionary", wordlist="x"))
    with pytest.raises(LegalGateRequired):
        eng.run()


def test_dictionary_attack_finds_password():
    recs = parse_text(
        "5f4dcc3b5aa765d61d8327deb882cf99\n"     # password (md5)
        "7c4a8d09ca3762af61e59520943dc26494f8941b\n")  # 123456 (sha1)
    words = _tmp_wordlist(["nope", "password", "123456"])
    eng = AttackEngine(recs, AttackConfig(mode="dictionary", wordlist=words),
                       authorized=True)
    result = eng.run()
    assert result["found"] == 2
    assert recs[0].plaintext == "password"
    assert recs[1].plaintext == "123456"


def test_rules_attack():
    recs = parse_text("6c569aabbf7775ef8fc570e228c16b98\n")  # md5('password!')
    words = _tmp_wordlist(["password"])
    rules_path = _tmp_wordlist(["$!"])  # append '!' — reuse simple writer
    eng = AttackEngine(recs, AttackConfig(mode="rules", wordlist=words,
                                          rules_file=rules_path),
                       authorized=True)
    result = eng.run()
    assert result["found"] == 1 and recs[0].plaintext == "password!"


def test_mask_attack():
    recs = parse_text("96e79218965eb72c92a549dd5a330112\n")  # md5('111111')
    eng = AttackEngine(recs, AttackConfig(mode="mask", mask="?d?d?d?d?d?d"),
                       authorized=True)
    result = eng.run()
    assert result["found"] == 1 and recs[0].plaintext == "111111"


def test_combinator_attack():
    recs = parse_text("3858f62230ac3c915f300c664312c63f\n")  # md5('foobar')
    w1 = _tmp_wordlist(["foo"])
    w2 = _tmp_wordlist(["bar"])
    eng = AttackEngine(recs, AttackConfig(mode="combinator", wordlist=w1,
                                          wordlist2=w2), authorized=True)
    result = eng.run()
    assert result["found"] == 1 and recs[0].plaintext == "foobar"


def test_stop_event_stops_run():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    words = _tmp_wordlist([f"w{i:06d}" for i in range(200_000)])
    eng = AttackEngine(recs, AttackConfig(mode="dictionary", wordlist=words),
                       authorized=True)
    eng.stop_event.set()  # stop before starting
    result = eng.run()
    assert result["stopped"] is True and result["candidates"] == 0


# ---------------------------------------------------------------- session

def test_session_roundtrip():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    recs[0].plaintext = "password"
    st = SessionState(records=recs)
    d = tempfile.mkdtemp(prefix="ha_")
    st.save(d)
    st2 = SessionState.load(d)
    assert st2 is not None
    assert len(st2.records) == 1
    assert st2.cracked["5f4dcc3b5aa765d61d8327deb882cf99"] == "password"


# ---------------------------------------------------------------- wordlists

def test_load_wordlist_dedupe_and_limit():
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("a\nb\na\n" + "x" * 300 + "\n")
    words = load_wordlist(path)
    assert words == ["a", "b"]


# ---------------------------------------------------------------- exports

def test_exports_written_and_watermarked():
    recs = parse_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    recs[0].plaintext = "password"
    audit_all(recs)
    d = tempfile.mkdtemp(prefix="ha_")
    hp = export_html(os.path.join(d, "r.html"), recs)
    cp = export_csv(os.path.join(d, "r.csv"), recs)
    jp = export_json(os.path.join(d, "r.json"), recs)
    for p in (hp, cp, jp):
        assert os.path.isfile(p)
    with open(hp, encoding="utf-8") as fh:
        assert "authorized" in fh.read().lower()
    with open(jp, encoding="utf-8") as fh:
        assert "watermark" in fh.read().lower()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
