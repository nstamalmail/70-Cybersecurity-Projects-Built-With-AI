"""Pure-Python MD4 implementation (RFC 1320).

Why: hashlib dropped MD4 on modern OpenSSL builds, but NTLM requires it.
This module is a faithful, independent reimplementation derived from the
public-domain reference code in RFC 1320 (Rivest, April 1992).

Correctness is pinned by the RFC's own test vectors in tests/test_core.py:

    MD4 ("")                                                       =
        31d6cfe0d16ae931b73c59d7e0c089c0
    MD4 ("a")                                                      =
        bde52cb31de33e46245e05fbdbd6fb24
    MD4 ("abc")                                                    =
        a448017aaf21d8525fc10ae87aa6729d
    MD4 ("message digest")                                         =
        d9130a8164549fe818874806e1c7014b
    MD4 ("abcdefghijklmnopqrstuvwxyz")                             =
        d79e1c308aa5bbcdeea8ed63df412da9
    MD4 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
        043f8582f241db351ce627e153e7f0e4
    MD4 ("1234567890" * 8)                                         =
        e33b4ddc9c38f2199c3e7b164fcc0536

Python ints are unbounded; every addition is masked with 0xffffffff to keep
C/UINT4 semantics.
"""

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF
_K2 = 0x5A827999  # sqrt(2)  — round 2 constant
_K3 = 0x6ED9EBA1  # sqrt(3)  — round 3 constant

_S1 = (3, 7, 11, 19)
_S2 = (3, 5, 9, 13)
_S3 = (3, 9, 11, 15)

# Block word indices for each round, in RFC order.
_R1_X = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
_R2_X = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
_R3_X = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)


def _lrot(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def md4(data: bytes) -> bytes:
    """Return the 16-byte MD4 digest of *data* (RFC 1320)."""
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # Step 1+2: padding and 64-bit little-endian length.
    bit_len = (len(data) & _MASK if len(data) < 0x2000000000000000
               else len(data)) * 8  # lengths beyond 2^61 bytes are absurd
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len & 0xFFFFFFFFFFFFFFFF)

    for off in range(0, len(msg), 64):
        x = struct.unpack_from("<16I", msg, off)

        a, b, c, d = a0, b0, c0, d0

        # Round 1: F(b,c,d) = (b & c) | (~b & d)
        for k, s in zip(_R1_X, _S1 * 4):
            a = _lrot((a + ((b & c) | (~b & d)) + x[k]) & _MASK, s)
            a, b, c, d = d, a, b, c

        # Round 2: G(b,c,d) = (b & c) | (b & d) | (c & d)
        for k, s in zip(_R2_X, _S2 * 4):
            a = _lrot((a + ((b & c) | (b & d) | (c & d)) + x[k] + _K2) & _MASK, s)
            a, b, c, d = d, a, b, c

        # Round 3: H(b,c,d) = b ^ c ^ d
        for k, s in zip(_R3_X, _S3 * 4):
            a = _lrot((a + (b ^ c ^ d) + x[k] + _K3) & _MASK, s)
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & _MASK
        b0 = (b0 + b) & _MASK
        c0 = (c0 + c) & _MASK
        d0 = (d0 + d) & _MASK

    return struct.pack("<4I", a0, b0, c0, d0)


def md4_hex(data: bytes) -> str:
    """Return the MD4 digest of *data* as lowercase hex."""
    return md4(data).hex()
