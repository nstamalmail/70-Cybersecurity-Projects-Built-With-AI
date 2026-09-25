"""NIST SP 800-63B aligned password strength audit.

Philosophy (per SP 800-63B): length and breach-list membership matter most;
character-class composition is surfaced as *information*, never enforcement.
Audit works with or without a known plaintext:

    - plaintext known   -> full content checks + verdict
    - plaintext unknown -> "UNTESTED" verdict with what-we-know notes
"""

from __future__ import annotations

import math
import os
from typing import List, Optional, Set

from .parser import HashRecord

MIN_LEN = 8           # SP 800-63B minimum
RECOMMENDED_LEN = 15  # suggested for accounts without MFA/rate-limiting

# Small builtin "top-common" set (synthetic/educational, see memory.md §2).
TOP_COMMON: Set[str] = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "abc123", "monkey", "dragon",
    "letmein", "welcome", "admin", "admin123", "root", "toor", "login",
    "passw0rd", "p@ssw0rd", "iloveyou", "sunshine", "princess", "football",
    "baseball", "master", "hello", "freedom", "whatever", "trustno1",
    "changeme", "secret", "summer", "winter", "spring", "autumn",
    "000000", "111111", "121212", "654321", "696969", "azerty",
}

KEYBOARD_WALKS = [
    "qwerty", "qwertz", "azerty", "qaz", "qazwsx", "1qaz", "2wsx", "3edc",
    "wasd", "asdf", "zxcv", "poiuy", "lkjh", "mnbv", "1234qwer", "qweasd",
]

# Sequences of 4+ consecutive characters to flag.
_SEQ = "abcdefghijklmnopqrstuvwxyz"
SEQUENCES = [
    _SEQ[i:i + 4] for i in range(len(_SEQ) - 3)
] + [
    "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890",
]


def shannon_entropy_bits(s: str) -> float:
    """Per-character Shannon entropy of *s*, times its length (total bits)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    h = 0.0
    for count in freq.values():
        p = count / n
        h -= p * math.log2(p)
    return h * n


def charset_space_bits(s: str) -> float:
    """Naive brute-force entropy estimate: len * log2(pool size)."""
    pool = 0
    if any(c.islower() for c in s):
        pool += 26
    if any(c.isupper() for c in s):
        pool += 26
    if any(c.isdigit() for c in s):
        pool += 10
    if any(not c.isalnum() for c in s):
        pool += 33
    if pool == 0:
        return 0.0
    return len(s) * math.log2(pool)


def _has_run(s: str, run: int = 4) -> bool:
    return any(c * run in s for c in set(s))


def _has_sequence(s: str, n: int = 4) -> Optional[str]:
    low = s.lower()
    for seq in SEQUENCES:
        if seq in low or seq[::-1] in low:
            return seq
    return None


def _has_walk(s: str) -> Optional[str]:
    low = s.lower()
    for walk in KEYBOARD_WALKS:
        if walk in low:
            return walk
    return None


def _is_common(s: str) -> bool:
    low = s.lower()
    if low in TOP_COMMON:
        return True
    # Common with trivial mutations (leetspeak 4->a, 0->o, 3->e, 1->l/i, 5->s)
    tr = str.maketrans("400513", "aoosli")
    return low.translate(tr) in TOP_COMMON


def audit_plaintext(pw: str) -> tuple:
    """Return (verdict, entropy_bits, findings list) for a known plaintext."""
    findings: List[str] = []
    verdict = "STRONG"

    if len(pw) < MIN_LEN:
        findings.append(f"Length {len(pw)} < {MIN_LEN} (SP 800-63B minimum)")
        verdict = "CRITICAL"
    elif len(pw) < RECOMMENDED_LEN:
        findings.append(f"Length {len(pw)} below recommended {RECOMMENDED_LEN}")

    if _is_common(pw):
        findings.append("Matches top-common password list (with mutations)")
        verdict = "CRITICAL"

    seq = _has_sequence(pw)
    if seq:
        findings.append(f"Contains sequence '{seq}'")
        if verdict == "STRONG":
            verdict = "WEAK"

    walk = _has_walk(pw)
    if walk:
        findings.append(f"Contains keyboard walk '{walk}'")
        if verdict == "STRONG":
            verdict = "WEAK"

    if _has_run(pw):
        findings.append("Contains 4+ repeated characters")
        if verdict == "STRONG":
            verdict = "WEAK"

    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    # Informational only (SP 800-63B discourages composition enforcement).
    if classes == 1 and len(pw) < RECOMMENDED_LEN:
        findings.append("Single character class (informational)")

    bits = shannon_entropy_bits(pw)
    if bits < 28 and verdict == "STRONG":
        verdict = "FAIR"
        findings.append(f"Low Shannon entropy ({bits:.1f} bits)")

    if verdict == "STRONG" and len(pw) < MIN_LEN + 2:
        verdict = "FAIR"

    return verdict, bits, findings


def audit_record(rec: HashRecord, wordlist_hits: Optional[Set[str]] = None) -> HashRecord:
    """Fill verdict/findings/entropy on *rec* and return it."""
    if rec.plaintext:
        verdict, bits, findings = audit_plaintext(rec.plaintext)
        rec.verdict, rec.entropy_bits, rec.findings = verdict, bits, findings
        return rec

    # Plaintext unknown — information from prior attack runs, if any.
    rec.entropy_bits = 0.0
    rec.findings = []
    if wordlist_hits and rec.digest_hex in wordlist_hits:
        rec.verdict = "CRITICAL"
        rec.findings.append("Cracked against builtin wordlist (untested further)")
    else:
        rec.verdict = "UNTESTED"
        if not rec.identified:
            rec.findings.append("Algorithm not identified — manual review needed")
    return rec


def audit_all(records: List[HashRecord], wordlist_hits: Optional[Set[str]] = None) -> List[HashRecord]:
    return [audit_record(r, wordlist_hits) for r in records]


SUMMARY_ORDER = ["CRITICAL", "WEAK", "FAIR", "STRONG", "UNTESTED"]


def summarize(records: List[HashRecord]) -> dict:
    out = {k: 0 for k in SUMMARY_ORDER}
    for r in records:
        out[r.verdict or "UNTESTED"] = out.get(r.verdict or "UNTESTED", 0) + 1
    return out
