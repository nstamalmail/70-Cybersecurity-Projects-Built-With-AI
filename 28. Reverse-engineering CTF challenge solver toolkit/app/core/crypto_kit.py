"""Crypto / Encoding Toolkit for RECT (architecture.md §3.3).

Encodings (base64/32/16/hex/url/rot13), XOR analysis (brute-force,
known-plaintext, key-length via Hamming distance), hash identification,
classical ciphers (Caesar, Vigenère), and a small-RSA helper.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import hmac
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------------ encodings
ENCODINGS = ["base64", "base32", "base16", "hex", "url", "rot13", "reverse"]


def encode(value: str, encoding: str) -> str:
    data = value.encode("utf-8")
    if encoding == "base64":
        return base64.b64encode(data).decode()
    if encoding == "base32":
        return base64.b32encode(data).decode()
    if encoding == "base16":
        return base64.b16encode(data).decode()
    if encoding == "hex":
        return data.hex()
    if encoding == "url":
        return urllib.parse.quote(value, safe="")
    if encoding == "rot13":
        return codecs.encode(value, "rot13")
    if encoding == "reverse":
        return value[::-1]
    raise ValueError(f"unknown encoding: {encoding}")


def decode(value: str, encoding: str) -> str:
    if encoding == "base64":
        pad = value + "=" * (-len(value) % 4)
        return base64.b64decode(pad).decode("utf-8", "replace")
    if encoding == "base32":
        pad = value.upper() + "=" * (-len(value) % 8)
        return base64.b32decode(pad).decode("utf-8", "replace")
    if encoding == "base16":
        return base64.b16decode(value.upper()).decode("utf-8", "replace")
    if encoding == "hex":
        return bytes.fromhex(value.strip()).decode("utf-8", "replace")
    if encoding == "url":
        return urllib.parse.unquote(value)
    if encoding == "rot13":
        return codecs.decode(value, "rot13")
    if encoding == "reverse":
        return value[::-1]
    raise ValueError(f"unknown encoding: {encoding}")


def auto_decode(value: str) -> List[Tuple[str, str]]:
    """Try every encoding; return the ones that decode cleanly."""
    results = []
    for enc in ENCODINGS:
        try:
            out = decode(value, enc)
        except Exception:
            continue
        if out and out.isprintable() and out != value:
            results.append((enc, out))
    return results


# ------------------------------------------------------------------ xor
def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single_byte_brute(data: bytes, limit: int = 256) -> List[Tuple[int, float, str]]:
    """Brute-force single-byte XOR; score by printable ratio + flag words."""
    results = []
    for k in range(limit):
        out = xor_bytes(data, bytes([k]))
        printable = sum(1 for b in out if 32 <= b < 127 or b in (9, 10, 13))
        score = printable / len(out) if out else 0.0
        if score > 0.7:
            results.append((k, score, out.decode("latin-1")))
    results.sort(key=lambda t: -t[1])
    return results[:10]


def xor_known_plaintext(data: bytes, known: bytes) -> Optional[bytes]:
    """Recover a repeating key from known plaintext at offset 0."""
    if len(known) > len(data):
        return None
    key = bytes(d ^ k for d, k in zip(data, known))
    return key


def xor_key_length(data: bytes, max_len: int = 32) -> List[Tuple[int, float]]:
    """Guess repeating-XOR key length via average Hamming distance (Kasiski-ish)."""
    scores: List[Tuple[int, float]] = []
    for klen in range(2, min(max_len, len(data) // 4) + 1):
        blocks = [data[i * klen:(i + 1) * klen]
                  for i in range(min(6, len(data) // klen))]
        if len(blocks) < 2:
            continue
        dists = []
        for i in range(len(blocks) - 1):
            a, b = blocks[i], blocks[i + 1]
            ham = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
            dists.append(ham / (len(a) * 8))
        scores.append((klen, sum(dists) / len(dists)))
    scores.sort(key=lambda t: t[1])
    return scores[:5]


# ------------------------------------------------------------------ hash identification
HASH_PATTERNS = [
    (r"^[0-9a-f]{32}$", "MD5 / MD4 / NTLM / RIPEMD-128"),
    (r"^[0-9a-f]{40}$", "SHA-1 / RIPEMD-160"),
    (r"^[0-9a-f]{56}$", "SHA-224 / SHA-512/224"),
    (r"^[0-9a-f]{64}$", "SHA-256 / BLAKE2s-256"),
    (r"^[0-9a-f]{96}$", "SHA-384"),
    (r"^[0-9a-f]{128}$", "SHA-512 / Whirlpool"),
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53,60}$", "bcrypt"),
    (r"^\$6\$rounds=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", "sha512crypt"),
    (r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", "sha512crypt"),
    (r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", "sha256crypt"),
    (r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$", "md5crypt"),
    (r"^\$argon2(id|i|d)\$", "Argon2"),
    (r"^\$scrypt\$", "scrypt"),
]


def identify_hash(value: str) -> List[str]:
    out = []
    for pattern, name in HASH_PATTERNS:
        if re.match(pattern, value.strip()):
            out.append(name)
    return out or ["unknown / custom"]


def hash_string(value: str, algo: str) -> str:
    return hashlib.new(algo, value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ classical ciphers
def caesar(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def caesar_all_shifts(text: str) -> List[Tuple[int, str]]:
    return [(s, caesar(text, s)) for s in range(1, 26)]


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = "".join(c for c in key.lower() if "a" <= c <= "z")
    if not key:
        return text
    out = []
    ki = 0
    for ch in text:
        if "a" <= ch <= "z":
            shift = ord(key[ki % len(key)]) - 97
            if decrypt:
                shift = -shift
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            shift = ord(key[ki % len(key)]) - 97
            if decrypt:
                shift = -shift
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def english_score(text: str) -> float:
    """Frequency-based English-likeness score (0..1)."""
    freq = "etaoinshrdlcumwfgypbvkjxqz"
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    top = [c for c in letters if c in freq[:8]]
    return len(top) / len(letters)


def caesar_best(text: str) -> Tuple[int, str, float]:
    scored = [(s, caesar(text, s), english_score(caesar(text, s)))
              for s in range(26)]
    scored.sort(key=lambda t: -t[2])
    s, txt, score = scored[0]
    return s, txt, score


# ------------------------------------------------------------------ rsa helper
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def try_factor_small_n(n: int, limit: int = 1_000_000) -> Optional[Tuple[int, int]]:
    """Trial-division factorization for small moduli (CTF-sized)."""
    if n % 2 == 0:
        return (2, n // 2)
    i = 3
    while i <= limit and i * i <= n:
        if n % i == 0:
            return (i, n // i)
        i += 2
    return None


def rsa_recover_private(p: int, q: int, e: int) -> Tuple[int, int, int]:
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return d, p, q


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def int_to_bytes(i: int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big") if length else b"\x00"


def analyze_rsa(n: str = "", e: str = "", c: str = "", p: str = "") -> str:
    """CTF RSA analyzer: try to recover the plaintext from public params."""
    report = []
    try:
        if not n or not e:
            return "Provide at least n and e."
        N = int(n, 0)
        E = int(e, 0)
        report.append(f"n bits: {N.bit_length()}")
        if p:
            P = int(p, 0)
            Q = N // P
            d, _, _ = rsa_recover_private(P, Q, E)
            report.append(f"p*q==n: {P * Q == N}")
            report.append(f"d recovered: {d}")
            if c:
                m = rsa_decrypt_int(int(c, 0), d, N)
                mb = int_to_bytes(m)
                report.append(f"plaintext bytes: {mb!r}")
                report.append(f"plaintext utf-8: {mb.decode('utf-8', 'replace')}")
        else:
            fac = try_factor_small_n(N)
            if fac:
                P, Q = fac
                report.append(f"n factored by trial division: p={P}, q={Q}")
                d, _, _ = rsa_recover_private(P, Q, E)
                report.append(f"d recovered: {d}")
                if c:
                    m = rsa_decrypt_int(int(c, 0), d, N)
                    mb = int_to_bytes(m)
                    report.append(f"plaintext utf-8: {mb.decode('utf-8', 'replace')}")
            else:
                report.append("n not factorable by trial division (need p/q).")
    except Exception as exc:
        report.append(f"error: {exc}")
    return "\n".join(report)
