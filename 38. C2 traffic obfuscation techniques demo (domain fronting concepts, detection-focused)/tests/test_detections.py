"""Detection-engine tests: crafted flows probe each rule positively and negatively."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detections import (DEFAULT_THRESHOLDS, assign_verdicts, run_all)
from src.simulator.flows import App, FlowRecord

TH = DEFAULT_THRESHOLDS


def _http(ts, src="192.0.2.11", dst="198.51.100.10", sni="cdn.example",
          host="cdn.example", uri="/", ja3="browser-chrome-stable",
          body=b"", ttl=64, layers=None) -> FlowRecord:
    return FlowRecord(ts=ts, src=src, dst=dst, sport=45000, dport=443,
                      proto="tcp", app=App.HTTP, sni=sni, host=host, uri=uri,
                      ja3=ja3, body=body, ttl=ttl,
                      encoding_layers=layers or [], family="test")


def _ntp(ts, src="192.0.2.20") -> FlowRecord:
    return FlowRecord(ts=ts, src=src, dst="198.51.100.53", sport=123, dport=123,
                      proto="udp", app=App.NTP, host="time.example", family="ntp")


def _rules(flows):
    findings, _counts = run_all(flows)
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------- D1
def test_d1_fires_on_sni_host_mismatch():
    flows = [_http(1.0, sni="cdn.example", host="203.0.113.10")]
    assert "D1" in _rules(flows)


def test_d1_silent_when_sni_equals_host():
    flows = [_http(t, sni="cdn.example", host="cdn.example") for t in range(20)]
    assert "D1" not in _rules(flows)


# ---------------------------------------------------------------- D2
def test_d2_fires_on_tight_beacon():
    flows = [_http(1000.0 + i * 60.0 + (0.1 if i % 2 else -0.1),
                   src="192.0.2.42") for i in range(20)]
    assert "D2" in _rules(flows)


def test_d2_silent_on_irregular_or_sparse():
    assert "D2" not in _rules([_http(1.0 * i * i) for i in range(30)])   # accelerating
    assert "D2" not in _rules([_http(1.0 + i * 60) for i in range(4)])   # too few


def test_d2_ignores_benign_ntp_rhythm():
    flows = [_ntp(0.0 + i * 1024.0) for i in range(30)]
    assert "D2" not in _rules(flows)   # ntp excluded from D2 grouping; D9 handles it


# ---------------------------------------------------------------- D3
def test_d3_fires_on_implant_fingerprint_fanout():
    flows = [_http(float(i), dst=f"198.51.100.1{i}", ja3="implant-x") for i in range(5)]
    assert "D3" in _rules(flows)


def test_d3_ignores_browser_baseline():
    flows = [_http(float(i), dst=f"198.51.100.1{i}") for i in range(5)]
    assert "D3" not in _rules(flows)


# ---------------------------------------------------------------- D4
def test_d4_fires_on_high_entropy_body():
    import random
    rng = random.Random(7)
    body = bytes(rng.randrange(256) for _ in range(2048))
    findings, _ = run_all([_http(1.0, body=body)])
    assert "D4" in {f.rule_id for f in findings}


def test_d4_silent_on_text_body():
    findings, _ = run_all([_http(1.0, body=b"<html>" + b"hello world " * 200 + b"</html>")])
    assert "D4" not in {f.rule_id for f in findings}


# ---------------------------------------------------------------- D5
def test_d5_fires_on_dga_name():
    import random
    rng = random.Random(3)
    dns = FlowRecord(ts=1.0, src="192.0.2.30", dst="198.51.100.53", sport=40001,
                     dport=53, proto="udp", app=App.DNS,
                     host="bv7xk2qmzp41.invalid", family="dga_decoy")
    assert "D5" in _rules([dns])


def test_d5_silent_on_normal_host():
    dns = FlowRecord(ts=1.0, src="192.0.2.30", dst="198.51.100.53", sport=40001,
                     dport=53, proto="udp", app=App.DNS,
                     host="portal.example", family="dns")
    assert "D5" not in _rules([dns])


# ---------------------------------------------------------------- D6
def test_d6_fires_on_rare_sni_fanout():
    flows = [_http(float(i), dst=f"198.51.100.1{i}",
                   sni="updates.example", ja3="implant-x") for i in range(5)]
    assert "D6" in _rules(flows)


# ---------------------------------------------------------------- D7
def findings_all(flows):
    f, _ = run_all(flows)
    return f


def test_d7_fires_on_long_and_layered():
    flows = [_http(1.0, uri="x" * 200), _http(2.0, layers=["base64", "xor"])]
    assert "D7" in _rules(flows)


# ---------------------------------------------------------------- D8
def test_d8_fires_on_low_ttl_cohort():
    flows = [_http(float(i), dst=f"198.51.100.1{i}", ttl=57) for i in range(4)]
    assert "D8" in _rules(flows)


def test_d8_silent_on_normal_ttl():
    flows = [_http(float(i), dst=f"198.51.100.1{i}", ttl=127) for i in range(4)]
    assert "D8" not in _rules(flows)


# ---------------------------------------------------------------- D9
def test_d9_reports_benign_ntp_as_controlled():
    flows = [_ntp(float(i * 1024)) for i in range(30)]
    d9 = [f for f in findings_all(flows) if f.rule_id == "D9"]
    assert d9 and d9[0].score == 0
    assert "correctly stayed below" in d9[0].evidence


# ---------------------------------------------------------------- verdicts
def test_verdict_bands():
    flows = [_http(1.0, sni="cdn.example", host="203.0.113.10"),    # D1 → malicious
             _http(2.0, layers=["base64", "xor"])]                  # D7 → suspicious
    findings, counts = run_all(flows)
    assert counts["malicious"] == 1 and counts["suspicious"] == 1


def test_deterministic_scoring():
    flows = [_http(float(i), sni="cdn.example", host="203.0.113.10") for i in range(5)]
    f1, c1 = run_all([FlowRecord(**vars(x)) for x in flows])
    f2, c2 = run_all([FlowRecord(**vars(x)) for x in flows])
    assert c1 == c2
