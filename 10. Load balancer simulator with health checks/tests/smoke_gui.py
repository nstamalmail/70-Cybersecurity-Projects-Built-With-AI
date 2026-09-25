"""Smoke test for LBSim: engine algorithms, health checker, reports, GUI, import."""
import os
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "src", "lbsim"))

import engine  # noqa: E402
import reporting  # noqa: E402


def test_algorithms():
    pool = engine.BackendPool()
    for i, w in enumerate([1, 1, 2]):
        pool.add(engine.SimulatedBackend(f"id{i}", f"b{i}", f"10.0.0.1{i}:80", w))

    rr = engine.RoundRobin(pool)
    picks = [rr.pick("1.2.3.4").name for _ in range(6)]
    assert picks == ["b0", "b1", "b2", "b0", "b1", "b2"], picks

    wrr = engine.WeightedRoundRobin(pool)
    counts = {}
    for _ in range(40):
        b = wrr.pick("1.2.3.4")
        counts[b.name] = counts.get(b.name, 0) + 1
    assert counts["b2"] == 20 and counts["b0"] == 10, counts

    lc = engine.LeastConnections(pool)
    pool.backends[0].active_connections = 5
    assert lc.pick().name == "b1"

    ih = engine.IPHash(pool)
    assert ih.pick("9.9.9.9").name == ih.pick("9.9.9.9").name
    print("algorithms: OK")


def test_health_checker():
    pool = engine.BackendPool()
    bad = engine.SimulatedBackend("x1", "broken", "10.0.0.99:80", 1, "http_500")
    good = engine.SimulatedBackend("x2", "fine", "10.0.0.98:80", 1, "healthy")
    pool.add(bad)
    pool.add(good)
    cfg = engine.HealthCheckConfig(check_type="http", interval_seconds=0.3,
                                   fall_threshold=2, rise_threshold=2)
    hc = engine.HealthChecker(pool, cfg)
    hc.start()
    deadline = time.monotonic() + 5
    while bad.health == "UP" and time.monotonic() < deadline:
        time.sleep(0.1)
    hc.stop()
    assert bad.health == "DOWN", "http_500 backend should fall after threshold"
    assert good.health == "UP"
    assert hc.log, "health check log should not be empty"
    print("health checker: OK (bad backend fell to DOWN)")


def test_reports():
    result = engine.SimulationResult(
        simulation_id="sim-test", timestamp=__import__("datetime").datetime.now(),
        algorithm="round_robin",
        health_check_config=engine.HealthCheckConfig().to_dict(),
        backends=[b.to_dict() for b in [
            engine.SimulatedBackend("a", "web-a", "10.0.0.1:80", 1),
            engine.SimulatedBackend("b", "web-b", "10.0.0.2:80", 1)]],
        total_requests=100,
        state_transitions=[{"timestamp": "t1", "backend": "web-b",
                            "from_state": "UP", "to_state": "DOWN",
                            "reason": "fall_threshold"}],
        health_check_log=[], duration_seconds=12.5,
    )
    out = os.path.join(HERE, "reports")
    for fmt in ("txt", "json", "csv", "html"):
        p = reporting.export(result, fmt, os.path.join(out, f"smoke.{fmt}"))
        assert os.path.getsize(p) > 100, f"{fmt} report too small"
    p = reporting.export(result, "pdf", os.path.join(out, "smoke.pdf"))
    with open(p, "rb") as fh:
        assert fh.read(5) == b"%PDF-", "pdf magic missing"
    print("reports (5 formats): OK")


def test_import_and_roundtrip():
    import json
    sample = os.path.join(HERE, "sample_data", "simulation_web_farm.json")
    with open(sample, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    result = engine.simulation_from_dict(data)
    assert result.total_requests == 2400
    assert len(result.backends) == 3
    txt = reporting.to_txt(result)
    assert "web-c" in txt and "1,220" in txt.replace(",", ",") or "1220" in txt
    print("sample import roundtrip: OK")


def test_gui():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    import main as gui

    app = QApplication.instance() or QApplication([])
    win = gui.MainWindow()
    win.show()
    assert win.tbl_backends.rowCount() == 3, "seeded backends missing"

    # run a very short live simulation
    win.sp_rate.setValue(20.0)
    win.sp_duration.setValue(3)
    win.sp_interval.setValue(0.5)
    win.sp_fall.setValue(1)
    win._start()
    assert win.hc is not None and win.tg is not None
    time.sleep(2.0)
    win._stop()
    assert win._result is not None and win._result.total_requests > 0
    assert win.tbl_dist.rowCount() == 3
    assert "Load Balancer Simulation Report" in win.txt_report.toPlainText()

    # export path smoke (write to temp inside project reports dir)
    import reporting as rep
    p = rep.export(win._result, "html", os.path.join(HERE, "reports", "smoke_gui.html"))
    assert os.path.getsize(p) > 200

    # import sample through the engine path (same code the menu uses)
    import json
    with open(os.path.join(HERE, "sample_data", "simulation_web_farm.json"),
              encoding="utf-8") as fh:
        res2 = engine.simulation_from_dict(json.load(fh))
    win._result = res2
    win._refresh_distribution(res2)
    win._render_report(res2)
    assert win.tbl_dist.rowCount() == 3
    win._stop_threads()
    win.close()
    print("GUI smoke: OK")


if __name__ == "__main__":
    test_algorithms()
    test_health_checker()
    test_reports()
    test_import_and_roundtrip()
    test_gui()
    print("ALL LBSIM SMOKE TESTS PASSED")
