"""Statistical property tests for jitter strategies."""
import random

from core.config import CheckinProfile
from core.jitter import next_delay, retry_delay


def mk(strategy, **kw):
    defaults = dict(name="t", strategy=strategy, base_delay_s=30.0,
                    jitter_s=10.0, cap_s=300.0, multiplier=3.0,
                    startup_spread_s=0.0, agent_count=1, seed=1)
    defaults.update(kw)
    return CheckinProfile(**defaults)


def test_fixed_is_deterministic():
    p = mk("fixed")
    rng = random.Random(0)
    assert all(next_delay(p, rng, {}) == 30.0 for _ in range(100))


def test_uniform_bounds_and_mean_shift():
    p = mk("uniform", base_delay_s=30, jitter_s=10)
    rng = random.Random(42)
    vals = [next_delay(p, rng, {}) for _ in range(5000)]
    assert all(30.0 <= v <= 40.0 for v in vals)
    mean = sum(vals) / len(vals)
    assert 34.5 <= mean <= 35.5  # expected 35 = base + jitter/2


def test_decorrelated_bounds_and_state():
    p = mk("decorrelated", base_delay_s=10, cap_s=50, multiplier=3.0)
    rng = random.Random(7)
    state = {}
    vals = [next_delay(p, rng, state) for _ in range(3000)]
    assert all(10.0 <= v <= 50.0 for v in vals)
    assert state["prev_delay"] == vals[-1]
    # without cap it would trend upward: with cap, stays within bounds
    assert max(vals) <= 50.0


def test_equal_jitter_floor():
    p = mk("equal", base_delay_s=30, jitter_s=15)
    rng = random.Random(3)
    vals = [next_delay(p, rng, {}) for _ in range(5000)]
    assert all(15.0 <= v <= 30.0 for v in vals)  # base/2 .. base/2+jitter
    mean = sum(vals) / len(vals)
    assert 21.5 <= mean <= 23.5  # expected 22.5


def test_retry_delay_grows_and_caps():
    p = mk("uniform", base_delay_s=8)
    rng = random.Random(11)
    d0 = retry_delay(p, 0, rng, cap_s=300)
    d5 = retry_delay(p, 5, rng, cap_s=300)
    d20 = retry_delay(p, 20, rng, cap_s=300)
    assert d0 < d5 <= d20 <= 300.0
    assert d20 <= 300.0 + 1e-9


def test_reproducibility_same_seed():
    p = mk("uniform")
    a = [next_delay(p, random.Random(99), {}) for _ in range(100)]
    b = [next_delay(p, random.Random(99), {}) for _ in range(100)]
    assert a == b
