"""Server behavior + metrics math tests."""
from core.config import CheckinProfile, ServerConfig
from core.server import SimulatedServer
from core.metrics import AgentMetrics, MetricsCollector, percentile


# ----------------------------------------------------------------- server
def test_server_success_path():
    cfg = ServerConfig(failure_rate=0.0, latency_min_ms=5, latency_max_ms=10)
    s = SimulatedServer(cfg, seed=1)
    r = s.handle_checkin(1, sim_time_s=0.0)
    assert r["ok"] and r["status"] == 200
    assert s.total == 1 and s.ok == 1


def test_server_rejection_rate_statistical():
    cfg = ServerConfig(failure_rate=0.5, latency_min_ms=1, latency_max_ms=2)
    s = SimulatedServer(cfg, seed=5)
    for i in range(2000):
        s.handle_checkin(1, sim_time_s=float(i))
    assert 0.45 <= s.rejection_rate() <= 0.55


def test_server_lockout_after_consecutive_failures():
    cfg = ServerConfig(failure_rate=1.0, latency_min_ms=1, latency_max_ms=1,
                       lockout_after_failures=2, lockout_duration_s=30.0,
                       bucket_s=10.0)
    s = SimulatedServer(cfg, seed=1)
    r1 = s.handle_checkin(1, sim_time_s=0.0)   # fail 1 -> 503
    r2 = s.handle_checkin(1, sim_time_s=1.0)   # fail 2 -> lockout opens, 503
    assert r1["ok"] is False and r1["status"] == 503
    assert r2["status"] == 503 and r2.get("lockout_opened")
    r3 = s.handle_checkin(1, sim_time_s=2.0)   # inside lockout -> 429
    assert r3["status"] == 429 and not r3["ok"]
    r4 = s.handle_checkin(1, sim_time_s=100.0)  # lockout expired -> 503 again
    assert r4["status"] == 503


def test_server_buckets():
    cfg = ServerConfig(bucket_s=10.0)
    s = SimulatedServer(cfg, seed=1)
    s.handle_checkin(1, sim_time_s=1.0)
    s.handle_checkin(1, sim_time_s=11.0)
    s.handle_checkin(2, sim_time_s=12.0)
    assert s.load_buckets() == [(0, 1), (1, 2)]


# ---------------------------------------------------------------- metrics
def test_percentile_interpolation():
    assert percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5
    assert percentile([10.0], 95) == 10.0
    assert percentile([], 50) is None
    vals = list(range(1, 101))  # 1..100
    assert percentile([float(v) for v in vals], 95) == 95.05


def test_agent_metrics_success_intervals():
    m = AgentMetrics(1, "p")
    m.record_success(10.0, 0.1)
    m.record_success(40.0, 0.2)
    m.record_success(70.5, 0.0)
    s = m.summary()
    assert s["checkins"] == 3 and s["successes"] == 3
    assert s["interval_mean_s"] == 30.25
    assert abs(s["drift_mean_s"] - 0.1) < 1e-9


def test_agent_metrics_retry_accounting():
    m = AgentMetrics(1, "p")
    m.record_success(10.0, 0.0)
    m.record_failure(20.0, 0.0)
    m.record_retry(21.0, 0.0)
    m.record_retry(22.0, 0.0)
    s = m.summary()
    assert s["successes"] == 1 and s["retries"] == 2
    assert s["attempts_p50"] == 3.0  # the success took 1 + 2 retries = 3 attempts


def test_collector_by_profile():
    c = MetricsCollector()
    c.register(1, "a")
    c.register(2, "a")
    c.register(3, "b")
    m = c.get(1)
    m.record_success(0.0, 0.0)
    m.record_success(30.0, 0.0)
    out = c.by_profile()
    assert out["a"]["agents"] == 2 and out["b"]["agents"] == 1
    assert out["a"]["interval_mean_s"] == 30.0
