"""Jitter strategy implementations — the actual study material.

Each strategy object is stateless; per-agent state (previous delay for
decorrelated) lives in the agent's runtime dict and is threaded through.
"""
from __future__ import annotations

import random
from typing import Dict, Any

from .config import CheckinProfile


def next_delay(profile: CheckinProfile, rng: random.Random, state: Dict[str, Any]) -> float:
    """Return the next check-in delay in seconds for one agent."""
    s = profile.strategy
    if s == "fixed":
        return profile.base_delay_s

    if s == "uniform":
        # base + U(0, jitter): simple spread, mean interval = base + jitter/2
        return profile.base_delay_s + rng.uniform(0.0, profile.jitter_s)

    if s == "decorrelated":
        prev = state.get("prev_delay", profile.base_delay_s)
        bound = max(prev * profile.multiplier, profile.base_delay_s)
        delay = rng.uniform(profile.base_delay_s, min(profile.cap_s, bound))
        state["prev_delay"] = delay
        return delay

    if s == "equal":
        # Equal/full jitter variant: base/2 floor + U(0, jitter)
        return profile.base_delay_s / 2.0 + rng.uniform(0.0, profile.jitter_s)

    raise ValueError(f"Unknown strategy: {s!r}")


def retry_delay(profile: CheckinProfile, attempt: int, rng: random.Random,
                cap_s: float = 300.0) -> float:
    """Exponential backoff with uniform jitter for a failed check-in.

    attempt is 0-based (first retry => attempt 0): base_retry * 2^attempt + U(0, quart).
    """
    base_retry = min(2.0, profile.base_delay_s / 4.0)
    backoff = min(cap_s, base_retry * (2 ** attempt))
    jitter = min(cap_s / 4.0, backoff / 4.0)
    return min(cap_s, backoff + rng.uniform(0.0, jitter))
