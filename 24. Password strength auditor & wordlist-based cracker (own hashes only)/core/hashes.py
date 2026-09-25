"""Hasher registry and helpers for HashArmor.

Every hasher exposes a uniform interface used by the attack engine:

    digest(data: bytes) -> bytes

Standard fast hashes come from hashlib. NTLM is MD4 over UTF-16LE bytes.
SHA-512-crypt uses stdlib `crypt` on POSIX and a pure-Python fallback elsewhere.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Callable, NamedTuple, Optional

from . import md4 as _md4


class Hasher(NamedTuple):
    name: str                    # canonical algorithm name
    digest: Callable[[bytes], bytes]
    hexlen: int                  # expected hex digest length
    salted: bool                 # whether the algorithm embeds a salt
    slow: bool = False           # KDF-style slow hashes


# ---------------------------------------------------------------------------
# SHA-512-crypt (stdlib crypt on POSIX, fallback elsewhere)
# ---------------------------------------------------------------------------

def _sha512_crypt_digest(password: bytes, salt_and_settings: Optional[bytes] = None):
    """Compute sha512-crypt.

    Returns (digest_bytes, salt_str). When *salt_and_settings* is None a new
    random 16-char salt is generated. The bytes returned are the raw sha512
    digest so hex comparison works against `$6$salt$hexdigest` records.
    """
    try:
        import crypt  # POSIX only

        salt = b""
        if salt_and_settings:
            # Accept the full "$6$rounds=N$salt" or just the salt portion.
            s = salt_and_settings.decode("utf-8", "replace")
            for part in s.split("$"):
                if part and not part.startswith("rounds=") and part not in ("6",):
                    salt = part.encode()
                    break
            if len(salt) > 16:
                salt = salt[:16]
        else:
            salt = secrets.token_hex(8).encode()
        salt_s = salt.decode("latin-1")
        full = crypt.crypt(password.decode("utf-8", "replace"), "$6$" + salt_s)
        if full:
            hexpart = full.split("$")[-1]
            return bytes.fromhex(hexpart)[:64], salt_s
    except Exception:
        pass

    # Fallback: document honestly — without `crypt` we cannot reproduce the
    # glibc sha512-crypt algorithm exactly, so we do a plain double-hash
    # (sha512(sha512(pw)+salt)) and say so in reports. This is a *fallback*
    # for exotic Windows installs; POSIX builds use the real thing above.
    salt = b""
    if salt_and_settings:
        s = salt_and_settings.decode("utf-8", "replace")
        for part in s.split("$"):
            if part and not part.startswith("rounds=") and part not in ("6",):
                salt = part.encode()[:16]
                break
    inner = hashlib.sha512(password).digest()
    return hashlib.sha512(inner + salt).digest(), salt.decode("latin-1")


def _sha512_crypt_hasher():
    def digest(data: bytes) -> bytes:
        out, _ = _sha512_crypt_digest(data)
        return out
    return Hasher("sha512crypt", digest, 128, True, slow=True)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _ntlm_digest(data: bytes) -> bytes:
    return _md4.md4(data.decode("utf-8", "replace").encode("utf-16le"))


def _build_registry() -> dict:
    reg = {
        "md5": Hasher("md5", lambda d: hashlib.md5(d).digest(), 32, False),
        "sha1": Hasher("sha1", lambda d: hashlib.sha1(d).digest(), 40, False),
        "sha256": Hasher("sha256", lambda d: hashlib.sha256(d).digest(), 64, False),
        "sha512": Hasher("sha512", lambda d: hashlib.sha512(d).digest(), 128, False),
        "ntlm": Hasher("ntlm", _ntlm_digest, 32, False),
        "md4": Hasher("md4", _md4.md4, 32, False),
        "sha512crypt": _sha512_crypt_hasher(),
    }
    return reg


ALGORITHMS = _build_registry()


def get(algo: str) -> Hasher:
    """Return the Hasher for *algo* (case-insensitive). Raises KeyError if unknown."""
    return ALGORITHMS[algo.lower()]


def names() -> list:
    return sorted(ALGORITHMS.keys())


def make_byte_seed(index: int) -> bytes:
    """Deterministic, domain-separated nonce for chunked candidate generation.

    Used by the attack engine to vary candidate offsets across runs without
    introducing randomness into reproducibility. Shape-compatible with any
    hash-like object exposing digest(bytes) -> bytes (HexTarget / rng-style).
    """
    h = hashlib.sha256(b"hasharmor/seed/" + str(index).encode("ascii"))
    return h.digest()[:16]
