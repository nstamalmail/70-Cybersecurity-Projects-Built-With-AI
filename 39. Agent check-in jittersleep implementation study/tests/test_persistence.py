"""Persistence tests: state round-trip, memory append-only, atomicity."""
import os

from core.config import AppConfig, CheckinProfile, ServerConfig
from persistence.state import StateStore, atomic_write
from persistence.memory import MemoryStore


def make_config():
    return AppConfig(
        profiles=[CheckinProfile(name="p1", strategy="uniform", base_delay_s=30,
                                 jitter_s=10, agent_count=3, seed=42),
                  CheckinProfile(name="p2", strategy="fixed", base_delay_s=60,
                                 agent_count=2, seed=99)],
        server=ServerConfig(failure_rate=0.1, lockout_after_failures=3),
        seed=7, duration_s=120.0, speed=10.0,
    )


def make_summary():
    return {
        "elapsed_sim_s": 120.0, "agents": 5,
        "server": {"total": 40, "ok": 36, "rejected": 4, "locked": 2,
                   "rejection_rate": 0.1},
        "profiles": {
            "p1": {"agents": 3, "checkins": 24, "successes": 20, "failures": 2,
                   "retries": 2, "interval_mean_s": 35.1, "interval_std_s": 5.8,
                   "drift_p50_s": 0.001, "drift_p95_s": 0.004,
                   "drift_max_s": 0.009},
            "p2": {"agents": 2, "checkins": 16, "successes": 16, "failures": 0,
                   "retries": 0, "interval_mean_s": 60.0, "interval_std_s": 0.0,
                   "drift_p50_s": 0.0005, "drift_p95_s": 0.002,
                   "drift_max_s": 0.003},
        },
    }


def test_state_round_trip(tmp_path):
    st = StateStore(str(tmp_path))
    cfg = make_config()
    st.save(cfg, make_summary(), events_count=57, note="test")
    loaded = st.load()
    assert loaded["config_fingerprint"] == cfg.fingerprint()
    cfg2 = st.load_config()
    assert cfg2.to_dict() == cfg.to_dict()


def test_state_md_contains_snapshot(tmp_path):
    st = StateStore(str(tmp_path))
    st.save(make_config(), make_summary(), 57, note="hello")
    text = (tmp_path / "state.md").read_text(encoding="utf-8")
    assert "# State — Agent Check-in Jitter/Sleep Study" in text
    assert "config_fingerprint" in text
    assert "hello" in text
    assert (tmp_path / "state" / "last-session.json").exists()


def test_memory_is_append_only(tmp_path):
    mem = MemoryStore(str(tmp_path))
    cfg = make_config()
    id1 = mem.append_run(cfg, make_summary(), events=[])
    id2 = mem.append_run(cfg, make_summary(), events=[])
    assert id1 != id2
    text = (tmp_path / "memory.md").read_text(encoding="utf-8")
    assert text.count(f"## Run {id1}") == 1
    assert text.count(f"## Run {id2}") == 1
    assert text.index(f"## Run {id1}") < text.index(f"## Run {id2}")


def test_run_export_json(tmp_path):
    mem = MemoryStore(str(tmp_path))
    path = mem.export_run(make_config(), make_summary(),
                          [{"type": "start", "sim_t": 0.0}])
    assert os.path.exists(path)
    import json
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["config"]["profiles"][0]["name"] == "p1"
    assert data["events"][0]["type"] == "start"


def test_atomic_write_leaves_no_tmp(tmp_path):
    target = tmp_path / "x.md"
    atomic_write(str(target), "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith(".tmp-")]
    assert leftovers == []
