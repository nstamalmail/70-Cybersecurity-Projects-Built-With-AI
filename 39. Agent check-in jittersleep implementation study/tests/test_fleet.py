"""Fleet integration tests: end-to-end run, reproducibility, stop responsiveness."""
import threading
import time

from core.config import AppConfig, CheckinProfile, ServerConfig
from core.fleet import Fleet


def run(config):
    fleet = Fleet(config)
    fleet.start()
    while fleet.is_running():
        time.sleep(0.02)
    fleet.stop()
    return fleet


def test_fleet_runs_and_records():
    config = AppConfig(
        profiles=[CheckinProfile(name="p", strategy="uniform", base_delay_s=0.2,
                                 jitter_s=0.1, agent_count=3, seed=1)],
        server=ServerConfig(failure_rate=0.0, bucket_s=1.0),
        seed=1, duration_s=1.0, speed=10.0)
    fleet = run(config)
    s = fleet.summary()
    assert s["agents"] == 3
    assert s["server"]["total"] > 0
    assert s["server"]["ok"] == s["server"]["total"]  # no failures configured
    types = {e["type"] for e in fleet.events()}
    assert "start" in types and "checkin" in types and "end" in types


def test_fleet_reproducible_same_seed():
    def make():
        return AppConfig(
            profiles=[CheckinProfile(name="p", strategy="uniform",
                                     base_delay_s=0.1, jitter_s=0.05,
                                     agent_count=2, seed=7)],
            server=ServerConfig(failure_rate=0.3, bucket_s=1.0),
            seed=7, duration_s=1.0, speed=20.0)

    f1, f2 = run(make()), run(make())
    s1, s2 = f1.summary(), f2.summary()
    assert s1["server"]["total"] == s2["server"]["total"]
    assert s1["server"]["ok"] == s2["server"]["ok"]


def test_fleet_stop_is_responsive():
    config = AppConfig(
        profiles=[CheckinProfile(name="p", strategy="fixed", base_delay_s=300,
                                 agent_count=2, seed=1)],
        server=ServerConfig(), seed=1, duration_s=0.0, speed=1.0)
    fleet = Fleet(config)
    fleet.start()
    time.sleep(0.3)
    t0 = time.monotonic()
    fleet.stop(join_timeout=3.0)
    took = time.monotonic() - t0
    assert took < 2.0, f"stop took {took:.2f}s — sleep chunking broken"


def test_fleet_retry_events_on_failure():
    config = AppConfig(
        profiles=[CheckinProfile(name="p", strategy="fixed", base_delay_s=0.1,
                                 agent_count=1, seed=3)],
        server=ServerConfig(failure_rate=1.0, lockout_after_failures=0,
                            bucket_s=1.0),
        seed=3, duration_s=0.5, speed=10.0)
    fleet = run(config)
    types = {e["type"] for e in fleet.events()}
    assert "retry" in types
