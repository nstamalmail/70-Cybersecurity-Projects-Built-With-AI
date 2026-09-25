import time

from hids.core.models import Alert, FileRecord


def _rec(path, size=10, sha="a" * 64):
    return FileRecord(path=path, size=size, mtime=123.0, sha256=sha)


def test_baseline_roundtrip(env):
    config, db, bus = env
    db.replace_baseline([_rec("C:/a.txt"), _rec("C:/b.txt")])
    rows = db.all_baseline()
    assert len(rows) == 2
    assert db.baseline_count() == 2

    db.upsert_baseline([_rec("C:/a.txt", size=99, sha="b" * 64)])
    db.remove_baseline(["C:/b.txt"])
    rows = {r["path"]: r for r in db.all_baseline()}
    assert db.baseline_count() == 1
    assert rows["C:/a.txt"]["size"] == 99
    assert rows["C:/a.txt"]["sha256"] == "b" * 64


def test_baseline_fingerprint_detects_change(env):
    config, db, bus = env
    db.replace_baseline([_rec("C:/a.txt")])
    fp1 = db.baseline_fingerprint()
    db.upsert_baseline([_rec("C:/a.txt", sha="c" * 64)])
    fp2 = db.baseline_fingerprint()
    assert fp1 != fp2


def test_alerts_add_list_filter_ack(env):
    config, db, bus = env
    db.add_alert(Alert(time.time(), "CRITICAL", "FIM", "file_burst", "burst!", {}))
    db.add_alert(Alert(time.time(), "INFO", "PROCESS", "new_process", "new proc", {"pid": 1}))

    assert db.alert_counts()["TOTAL"] == 2
    assert len(db.alerts(severity="CRITICAL")) == 1
    assert len(db.alerts(category="PROCESS")) == 1
    assert len(db.alerts(search="burst")) == 1
    assert len(db.alerts(search="zzz")) == 0

    first = db.alerts(limit=1)[0]
    db.set_acknowledged(first.id, 1)
    assert db.alerts(limit=1)[0].acknowledged == 1

    db.delete_alerts([first.id])
    assert db.alert_counts()["TOTAL"] == 1

    db.clear_alerts()
    assert db.alert_counts()["TOTAL"] == 0


def test_meta_and_scans(env):
    config, db, bus = env
    assert db.get_meta("x") is None
    db.set_meta("x", "42")
    assert db.get_meta("x") == "42"

    sid = db.start_scan()
    db.finish_scan(sid, {"started": time.time() - 1, "files_scanned": 5,
                         "added": 1, "modified": 2, "deleted": 0, "errors": 0})
    row = db.last_scan()
    assert row["files_scanned"] == 5
    assert row["modified"] == 2
