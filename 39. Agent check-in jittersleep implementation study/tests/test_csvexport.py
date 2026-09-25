"""Tests for persistence.csvexport."""
import csv
import os

from core.config import AppConfig, CheckinProfile, ServerConfig
from core.fleet import Fleet
from persistence.csvexport import (AGENT_FIELDS, PROFILE_FIELDS, export_agent_stats,
                                   export_all, export_all_to_base,
                                   export_profile_metrics, render_csv, split_base)


def make_collector():
    from core.metrics import MetricsCollector
    c = MetricsCollector()
    a = c.register(1, "alpha")
    a.record_success(0.0, 0.001)
    a.record_success(30.0, 0.002)
    a.record_failure(40.0, 0.003)
    b = c.register(2, "beta")
    b.record_success(0.0, 0.0)
    b.record_success(60.0, 0.0)
    return c


def make_summary():
    return {
        "elapsed_sim_s": 60.0, "agents": 2,
        "server": {"total": 5, "ok": 4, "rejected": 1, "locked": 0,
                   "rejection_rate": 0.2},
        "profiles": {
            "alpha": {"agents": 1, "checkins": 3, "successes": 2, "failures": 1,
                      "retries": 0, "interval_mean_s": 30.0, "interval_std_s": 0.0,
                      "drift_p50_s": 0.002, "drift_p95_s": 0.003,
                      "drift_max_s": 0.003},
            "beta": {"agents": 1, "checkins": 2, "successes": 2, "failures": 0,
                     "retries": 0, "interval_mean_s": 60.0, "interval_std_s": 0.0,
                     "drift_p50_s": 0.0, "drift_p95_s": 0.0, "drift_max_s": 0.0},
        },
    }


def test_render_csv_none_and_float_formatting():
    text = render_csv(["a", "b"], [{"a": 1.23456789, "b": None}])
    lines = text.strip().splitlines()
    assert lines[0] == "a,b"
    assert lines[1] == "1.234568,"  # None -> empty cell


def test_export_profile_metrics_content(tmp_path):
    path = export_profile_metrics(make_summary(), run_id="T1", out_dir=str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert [r["profile"] for r in rows] == ["alpha", "beta"]  # summary order kept
    assert rows[0]["run_id"] == "T1"
    assert rows[0]["interval_mean_s"] == "30.000000"
    assert set(rows[0].keys()) == set(PROFILE_FIELDS)


def test_export_agent_stats_content(tmp_path):
    path = export_agent_stats(make_collector(), run_id="T2", out_dir=str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert [r["agent_id"] for r in rows] == ["1", "2"]
    assert set(rows[0].keys()) == set(AGENT_FIELDS)
    # raw counters: failures and retries reported separately (no merging)
    alpha = rows[0]
    assert alpha["failures"] == "1" and alpha["retries"] == "0"
    assert alpha["checkins"] == "3" and alpha["successes"] == "2"
    # agent with no intervals -> empty cells, not 'None'
    assert rows[1]["attempts_p95"] != "None"
    assert alpha["interval_mean_s"] == "30.000000"
    assert alpha["drift_p95_s"] != ""


def test_export_all_same_run_id(tmp_path):
    paths = export_all(make_summary(), make_collector(),
                       run_id="T3", out_dir=str(tmp_path))
    assert len(paths) == 2
    assert all(os.path.exists(p) for p in paths)
    names = [os.path.basename(p) for p in paths]
    assert names == ["metrics_T3.csv", "agents_T3.csv"]


def test_export_all_default_run_id(tmp_path):
    paths = export_all(make_summary(), make_collector(), out_dir=str(tmp_path))
    assert len({os.path.basename(p).split("_")[-1] for p in paths}) == 1  # same id


def test_split_base_variants():
    # split_base preserves the input's path separators (splitext semantics)
    # plain name, auto extension
    assert split_base("out/run") == ("out/run", ".csv")
    # proper .csv path
    assert split_base("out/run.csv") == ("out/run", ".csv")
    # known pair suffixes are stripped so the pair stays matched
    assert split_base("out/run_metrics.csv") == ("out/run", ".csv")
    assert split_base("out/run_agents.csv") == ("out/run", ".csv")
    # odd extension is tolerated and normalized to .csv
    assert split_base("out/run.txt") == ("out/run.txt", ".csv")
    # windows-style separators also preserved
    assert split_base("C:/out/run.csv") == ("C:/out/run", ".csv")


def test_export_all_to_base_writes_pair(tmp_path):
    base = str(tmp_path / "experiment1")
    paths = export_all_to_base(make_summary(), make_collector(), base)
    assert [os.path.basename(p) for p in paths] == [
        "experiment1_metrics.csv", "experiment1_agents.csv"]
    with open(paths[0], newline="", encoding="utf-8") as f:
        prows = list(csv.DictReader(f))
    with open(paths[1], newline="", encoding="utf-8") as f:
        arows = list(csv.DictReader(f))
    assert [r["profile"] for r in prows] == ["alpha", "beta"]
    assert len(arows) == 2
    assert prows[0]["run_id"] == "experiment1"  # base name becomes run_id


def test_export_all_to_base_tolerates_suffix_and_overwrites(tmp_path):
    base = str(tmp_path / "run_metrics.csv")
    p1 = export_all_to_base(make_summary(), make_collector(), base)
    assert os.path.basename(p1[0]) == "run_metrics.csv"
    before = os.path.getsize(p1[0])
    p2 = export_all_to_base(make_summary(), make_collector(), base)  # overwrite
    assert p2 == p1
    assert os.path.getsize(p2[0]) >= before


def test_csv_after_real_fleet_run(tmp_path):
    config = AppConfig(
        profiles=[CheckinProfile(name="p", strategy="fixed", base_delay_s=0.1,
                                 agent_count=2, seed=1)],
        server=ServerConfig(failure_rate=0.5, bucket_s=1.0),
        seed=1, duration_s=0.5, speed=10.0)
    fleet = Fleet(config)
    fleet.start()
    import time
    while fleet.is_running():
        time.sleep(0.02)
    fleet.stop()
    paths = export_all(fleet.summary(), fleet.metrics,
                       run_id="LIVE", out_dir=str(tmp_path))
    with open(paths[1], newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2  # one row per agent
    assert sum(int(r["checkins"]) for r in rows) == fleet.server.total
