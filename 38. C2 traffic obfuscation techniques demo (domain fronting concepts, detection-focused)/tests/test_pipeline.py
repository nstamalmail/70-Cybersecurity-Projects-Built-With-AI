"""End-to-end pipeline tests across all scenarios (deterministic seeds)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.pipeline import run_pipeline
from src.simulator.pcap import PcapInfo


def test_fronting_scenario_core_signals():
    res = run_pipeline("c2_domain_fronting", seed=1337)
    rules = {f.rule_id for f in res.findings}
    assert "D1" in rules, "fronting scenario must trip the SNI/Host disjunction rule"
    assert res.verdict_counts["malicious"] > 0
    # the disjunction must be present in the raw flows themselves
    assert any(f.sni and f.host and f.sni != f.host for f in res.flows)


def test_dga_scenario():
    res = run_pipeline("c2_dga", seed=42)
    rules = {f.rule_id for f in res.findings}
    assert "D1" in rules and ("D5" in rules or "D3" in rules)


def test_ransomware_scenario_no_fronting():
    res = run_pipeline("ransomware_checkin", seed=7)
    rules = {f.rule_id for f in res.findings}
    assert "D1" not in rules, "ransomware check-in must not front"
    assert "D4" in rules, "high-entropy check-in body must trip D4"


def test_benign_negative_control_stays_quiet():
    res = run_pipeline("benign_only", seed=5)
    counts = res.verdict_counts
    assert counts["malicious"] == 0 and counts["suspicious"] == 0, (
        f"negative control tripped: {counts}")


def test_all_scenarios_run_and_produce_pcap():
    for name in ("c2_domain_fronting", "c2_dga", "ransomware_checkin", "benign_only"):
        res = run_pipeline(name, seed=99)
        assert isinstance(res.pcap_info, PcapInfo)
        assert res.pcap_info.frames > 0
        assert Path(res.pcap_info.path).exists()
        for artifact in res.artifact_paths.values():
            assert Path(artifact).exists(), f"missing artifact {artifact}"


def test_determinism_same_seed_same_pcaphash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r1 = run_pipeline("c2_domain_fronting", seed=2024)
    r2 = run_pipeline("c2_domain_fronting", seed=2024)
    assert r1.pcap_info.sha256 == r2.pcap_info.sha256
    assert r1.verdict_counts == r2.verdict_counts


def test_ztn_report_shape():
    res = run_pipeline("c2_domain_fronting", seed=1337)
    counts = res.ztn.counts
    assert counts["deny"] >= 1, "implant hosts must be denied"
    assert all(d.verdict in ("allow", "verify", "deny") for d in res.ztn.decisions)
