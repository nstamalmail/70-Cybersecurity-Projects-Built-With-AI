"""Encoding layers used by the synthetic campaign traffic.

These exist purely so decoy/campaign payloads have *realistic statistical shape*
(entropy, layering) for the detector to measure. They are didactic codecs only —
nothing here is operationally useful. Round-trip identity is property-tested.
"""
from __future__ import annotations

import base64
import codecs
import math

LayerName = str

DEFAULT_KEY = b"\x5a\xc3\x11\x7e"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Single-byte-stream XOR (didactic only)."""
    if not key:
        raise ValueError("key must be non-empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def b64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def b64_decode(data: bytes) -> bytes:
    return base64.b64decode(data, validate=False)


def rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("utf-8", "replace"), "rot13").encode()


LAYERS: dict[LayerName, tuple] = {
    # name: (encode_fn(bytes)->bytes, decode_fn(bytes)->bytes)
    "xor": (lambda d: xor_bytes(d, DEFAULT_KEY), lambda d: xor_bytes(d, DEFAULT_KEY)),
    "base64": (b64_encode, b64_decode),
    "rot13": (rot13, rot13),
}


def layered_encode(data: bytes, layers: list[str]) -> tuple[bytes, list[str]]:
    """Apply layers innermost-first; returns (encoded, applied_layer_names)."""
    out = data
    applied: list[str] = []
    for name in layers:
        enc, _ = LAYERS[name]
        out = enc(out)
        applied.append(name)
    return out, applied


def layered_decode(data: bytes, layers: list[str]) -> bytes:
    """Inverse of layered_encode (outermost first)."""
    out = data
    for name in reversed(layers):
        _, dec = LAYERS[name]
        out = dec(out)
    return out


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits/byte over the byte-frequency distribution."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent
