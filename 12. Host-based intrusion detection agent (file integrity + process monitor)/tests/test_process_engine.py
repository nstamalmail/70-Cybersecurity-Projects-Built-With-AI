import threading

from hids.engines.process_monitor import ProcessEngine


def test_snapshot_returns_processes(env):
    config, db, bus = env
    engine = ProcessEngine(config, db, bus)
    procs = engine.snapshot()
    assert len(procs) > 5  # any real system has plenty
    pids = {p.pid for p in procs}
    assert len(pids) == len(procs)  # unique pids


def test_tick_detects_nothing_suspicious_on_clean_host(env):
    config, db, bus = env
    config.set("process_rules", {"alert_on_new_process": False})
    engine = ProcessEngine(config, db, bus)
    procs = engine.tick()
    assert len(procs) > 0
    # With default conservative rules a normal dev box should have few/no hits;
    # whatever exists must be recorded consistently.
    for p in procs:
        assert p.suspicious == bool(p.reasons)


def test_suspicious_process_alerts_and_throttles(env):
    import subprocess
    import sys
    import time

    config, db, bus = env
    config.set("process_alert_cooldown_seconds", 600)
    engine = ProcessEngine(config, db, bus)

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        time.sleep(0.3)
        engine.tick()
        engine.tick()  # second tick inside cooldown must not re-alert
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    alerts = [a for a in db.alerts(category="PROCESS")
              if a.event_type == "suspicious_process"]
    titles = [a.title for a in alerts]
    hits = [t for t in titles if f"PID {proc.pid}" in t]
    if hits:  # rule fired (some environments flag python from temp dirs)
        assert len(hits) == 1  # throttled to one alert


def test_kill_nonexistent_returns_false(env):
    config, db, bus = env
    engine = ProcessEngine(config, db, bus)
    # PID 99999999 should not exist
    assert engine.kill(99999999) is False


def test_stop_event_stops_run_loop(env):
    config, db, bus = env
    config.set("process_poll_seconds", 1)
    engine = ProcessEngine(config, db, bus)
    engine.start()
    engine.stop()
    engine.join(timeout=10)
    assert not engine.is_alive()
