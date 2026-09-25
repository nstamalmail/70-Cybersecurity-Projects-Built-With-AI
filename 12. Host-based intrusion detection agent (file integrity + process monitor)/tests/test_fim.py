import os
import time

from hids.engines.fim import FimEngine


def _setup_paths(config, tmp_path, extra_exclude=None):
    monitored = str(tmp_path / "watched")
    config.set("monitored_paths", [monitored])
    excl = ["*.log"]
    if extra_exclude:
        excl += extra_exclude
    config.set("exclude_patterns", excl)
    return monitored


def _make_file(root, name, content="data"):
    p = os.path.join(root, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(content)
    return p


def test_baseline_and_change_detection(env, tmp_path):
    config, db, bus = env
    watched = _setup_paths(config, tmp_path)
    _make_file(watched, "a.txt", "one")
    _make_file(watched, "b.txt", "two")
    _make_file(watched, "sub/c.txt", "three")
    _make_file(watched, "noise.log", "excluded")

    engine = FimEngine(config, db, bus)
    result = engine.build_baseline()
    assert result["files"] == 3  # noise.log excluded
    assert db.baseline_count() == 3

    # No changes -> empty result
    assert engine.verify() == []

    # Modify
    _make_file(watched, "a.txt", "one-changed!!")
    # Add
    _make_file(watched, "d.txt", "new")
    # Delete
    os.remove(os.path.join(watched, "b.txt"))

    changes = {c.path: c.change for c in engine.verify()}
    assert changes[os.path.join(watched, "a.txt")] == "MODIFIED"
    assert changes[os.path.join(watched, "d.txt")] == "ADDED"
    assert changes[os.path.join(watched, "b.txt")] == "DELETED"

    # Baseline converged to current state (3 files: a, c, d)
    assert db.baseline_count() == 3

    # Alerts recorded with expected severities
    alerts = db.alerts(limit=100)
    by_type = {}
    for a in alerts:
        by_type.setdefault(a.event_type, []).append(a.severity)
    assert "MEDIUM" in by_type["file_modified"]
    assert "LOW" in by_type["file_added"]
    assert "MEDIUM" in by_type["file_deleted"]


def test_quick_scan_skips_untouched_files(env, tmp_path):
    config, db, bus = env
    watched = _setup_paths(config, tmp_path)
    _make_file(watched, "stable.txt", "stable")
    engine = FimEngine(config, db, bus)
    engine.build_baseline()
    # Quick scan: no changes, no alerts
    assert engine.verify(full=False) == []
    assert db.alert_counts()["TOTAL"] == 0


def test_burst_detection(env, tmp_path):
    config, db, bus = env
    config.set("burst_threshold", 3)
    config.set("burst_window_seconds", 60)
    config.set("burst_cooldown_seconds", 300)
    watched = _setup_paths(config, tmp_path)
    _make_file(watched, "a.txt")
    engine = FimEngine(config, db, bus)

    now = time.time()
    engine._register_burst(1, ts=now)
    engine._register_burst(1, ts=now + 1)
    assert not [a for a in db.alerts() if a.event_type == "file_burst"]
    engine._register_burst(1, ts=now + 2)  # total 3 >= threshold 3
    bursts = [a for a in db.alerts() if a.event_type == "file_burst"]
    assert len(bursts) == 1
    assert bursts[0].severity == "CRITICAL"
    # Cooldown suppresses immediate re-fire
    engine._register_burst(5, ts=now + 3)
    assert len([a for a in db.alerts() if a.event_type == "file_burst"]) == 1


def test_excluded_subtree_is_ignored(env, tmp_path):
    config, db, bus = env
    watched = _setup_paths(config, tmp_path, extra_exclude=["skipme/"])
    _make_file(watched, "a.txt")
    _make_file(watched, "skipme/hidden.txt")
    engine = FimEngine(config, db, bus)
    result = engine.build_baseline()
    assert result["files"] == 1
