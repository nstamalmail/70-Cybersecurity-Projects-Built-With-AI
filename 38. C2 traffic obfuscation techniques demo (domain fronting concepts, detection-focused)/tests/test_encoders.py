"""Encoder round-trip and entropy property tests."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.simulator.encoders import (layered_decode, layered_encode,
                                    shannon_entropy, xor_bytes)

PAYLOAD = b"didactic-payload-0123456789"


@pytest.mark.parametrize("layers", [
    ["base64"], ["xor"], ["rot13"],
    ["base64", "xor"], ["rot13", "base64", "xor"],
])
def test_layered_round_trip(layers):
    encoded, applied = layered_encode(PAYLOAD, layers)
    assert applied == layers
    assert layered_decode(encoded, applied) == PAYLOAD


def test_xor_is_involution_with_same_key():
    assert xor_bytes(xor_bytes(PAYLOAD, b"k3y"), b"k3y") == PAYLOAD


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0            # no information
    assert shannon_entropy(bytes(range(256)) * 4) > 7.95     # uniform == max
    assert shannon_entropy(b"a" * 900 + b"b" * 100) < 1.0    # heavily skewed


def test_layering_increases_length_for_base64():
    once, _ = layered_encode(PAYLOAD, ["base64"])
    twice, _ = layered_encode(PAYLOAD, ["base64", "base64"])
    assert len(twice) > len(once) > len(PAYLOAD)  # wrapper bulk — the D7 lesson
