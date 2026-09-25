import os
import time

import hids.engines.realtime as rt_mod
from hids.engines.fim import FimEngine
from hids.engines.realtime import RealtimeMonitor


class _Cfg:
    """Minimal config stub for standalone RealtimeMonitor unit tests."""

    def __init__(self, **kw):
        self.d = {
            "monitored_paths": [],
            "exclude_patterns": [],
            "realtime_debounce_seconds": 0.2,
            "max_file_size_mb": 1,
            "burst_threshold": 100,
            "burst_window_seconds": 60,
            "burst_cooldown_seconds": 300,
        }
        self.d.update(kw)

    def get(self, key, default=None):
        return self.d.get(key, default)


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_debounce_coalesces_rapid_events(tmp_path):
    cfg = _Cfg(monitored_paths=[str(tmp_path)])
    calls = []
    mon = RealtimeMonitor(cfg, calls.append)
    mon.start()
    try:
        target = str(tmp_path / "a.txt")
        for _ in range(6):
            mon.enqueue(target)
            time.sleep(0.01)
        assert _wait_until(lambda: len(calls) >= 1)
        time.sleep(0.6)  # well past the debounce window
        assert calls.count(target) == 1  # coalesced to a single processing
    finally:
        mon.stop()


def test_irrelevant_and_excluded_paths_are_filtered(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    cfg = _Cfg(monitored_paths=[str(watched)], exclude_patterns=["*.log"])
    calls = []
    mon = RealtimeMonitor(cfg, calls.append)
    mon.start()
    try:
        mon.enqueue(str(watched / "noise.log"))  # excluded pattern
        mon.enqueue(str(tmp_path / "outside.txt"))  # outside monitored root
        time.sleep(1.0)
        assert calls == []
    finally:
        mon.stop()


def test_fallback_without_watchdog(monkeypatch, tmp_path):
    cfg = _Cfg(monitored_paths=[str(tmp_path)])
    monkeypatch.setattr(rt_mod, "WATCHDOG_AVAILABLE", False)
    calls = []
    mon = RealtimeMonitor(cfg, calls.append)
    assert mon.start() is False  # no observer, but worker still active
    assert mon.active is False
    try:
        mon.enqueue(str(tmp_path / "y.txt"))
        assert _wait_until(lambda: len(calls) == 1)
    finally:
        mon.stop()


def test_process_path_now_states_and_dedup(env, tmp_path):
    config, db, bus = env
    watched = tmp_path / "watched"
    watched.mkdir()
    config.set("monitored_paths", [str(watched)])
    config.set("exclude_patterns", ["*.log"])
    engine = FimEngine(config, db, bus)

    p = os.path.normpath(os.path.abspath(str(watched / "f.txt")))
    with open(p, "w") as fh:
        fh.write("one")
    change = engine._process_path_now(p, ts=1000.0)
    assert change is not None and change.change == "ADDED"
    assert db.baseline_count() == 1

    # dedup suppresses the same (path, change) within 30 s
    assert engine._process_path_now(p, ts=1001.0) is None

    # identical content rewrite -> unchanged
    with open(p, "w") as fh:
        fh.write("one")
    assert engine._process_path_now(p, ts=1002.0) is None

    # modified content
    with open(p, "w") as fh:
        fh.write("two-longer")
    change = engine._process_path_now(p, ts=1003.0)
    assert change is not None and change.change == "MODIFIED"

    # deletion
    os.remove(p)
    change = engine._process_path_now(p, ts=1004.0)
    assert change is not None and change.change == "DELETED"
    assert db.baseline_count() == 0

    # excluded pattern is never verified
    p2 = str(watched / "x.log")
    with open(p2, "w") as fh:
        fh.write("log")
    assert engine._process_path_now(p2, ts=1005.0) is None


def test_realtime_end_to_end_alerts(env, tmp_path):
    config, db, bus = env
    watched = tmp_path / "watched"
    watched.mkdir()
    config.set("monitored_paths", [str(watched)])
    config.set("exclude_patterns", ["*.log"])
    config.set("realtime_debounce_seconds", 0.2)
    config.set("scan_interval_seconds", 3600)  # sweep effectively off — proves realtime

    target = watched / "doc.txt"
    target.write_text("v1")

    engine = FimEngine(config, db, bus)
    engine.build_baseline()
    assert db.baseline_count() == 1

    engine.start()
    try:
        assert _wait_until(lambda: engine.realtime_active, timeout=10), \
            "watchdog observer did not start"

        target.write_text("v2-longer")
        assert _wait_until(lambda: any(a.event_type == "file_modified"
                                       for a in db.alerts()), timeout=10), \
            "real-time modification not detected"

        (watched / "new.txt").write_text("fresh")
        assert _wait_until(lambda: any(a.event_type == "file_added"
                                       for a in db.alerts()), timeout=10), \
            "real-time creation not detected"

        os.remove(str(target))
        assert _wait_until(lambda: any(a.event_type == "file_deleted"
                                       for a in db.alerts()), timeout=10), \
            "real-time deletion not detected"
    finally:
        engine.stop()
        engine.join(timeout=10)
    assert not engine.is_alive()
