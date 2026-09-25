"""Pipeline orchestrator — one call runs the whole demo headless.

``run_pipeline`` is GUI-agnostic: the tkinter layer, ``--smoke`` mode, and the
tests all consume it. Everything is offline: the only filesystem writes are the
demo artifacts under ``artifacts/``.
"""
from __future__ import annotations

import csv
import json
import time as _time
from dataclasses import dataclass, field
from pathlib import Path

from src.detections import Finding, run_all
from src.safety import assert_safe
from src.simulator.flows import FlowRecord
from src.simulator.scenario import ScenarioConfig, get_scenario
from src.simulator.traffic import TrafficGen
from src.ztn import ZtnReport, evaluate_ztn, write_ztn_audit

ARTIFACT_DIR = Path("artifacts")


@dataclass
class PipelineResult:
    scenario: str
    seed: int
    flows: list[FlowRecord]
    findings: list[Finding]
    ztn: ZtnReport
    verdict_counts: dict[str, int]
    pcap_info: object
    artifact_paths: dict[str, str] = field(default_factory=dict)


def _variant_cfg(scenario: str, include_decoys: bool) -> ScenarioConfig:
    cfg = get_scenario(scenario)
    if include_decoys:
        return cfg
    # Decoy-free variant: keep the campaign, drop benign/NTP noise (negative-control mode).
    return ScenarioConfig(**{**cfg.__dict__, "include_benign": False, "include_ntp": False})


def _fmt_ts(ts: float) -> str:
    return (f"{_time.strftime('%Y-%m-%dT%H:%M:%S', _time.gmtime(ts))}."
            f"{int(ts % 1 * 1e6):06d}Z")


def _write_conn_log(flows: list[FlowRecord], path: Path) -> str:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("#separator \\x09\n#set_seed\tdemo\n")
        fh.write("#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tservice\tsni\thost\tfamily\tnote\tts_end\n")
        for f in flows:
            fh.write("\t".join([
                _fmt_ts(f.ts), f.src, f.dst, str(f.dport), f.proto, f.app,
                f.sni or "-", f.host or "-", f.family, f.note or "-",
                _fmt_ts(f.ts + 0.5),
            ]) + "\n")
    return str(path)


def _write_eve_json(flows: list[FlowRecord], path: Path) -> str:
    with path.open("w", encoding="utf-8") as fh:
        for f in flows:
            rec = {
                "timestamp": _fmt_ts(f.ts), "src_ip": f.src, "dest_ip": f.dst,
                "src_port": f.sport, "dest_port": f.dport, "proto": f.proto,
                "event_type": f.app, "family": f.family, "verdict": f.verdict,
                "sni": f.sni or None, "host": f.host or None, "http_uri": f.uri,
                "ja3": f.ja3 or None, "ja3s": f.ja3s or None,
                "ttl": f.ttl, "ip_id": f.ip_id,
            }
            fh.write(json.dumps(rec) + "\n")
    return str(path)


def _write_flows_csv(flows: list[FlowRecord], path: Path) -> str:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "src", "dst", "dport", "proto", "app", "sni", "host",
                    "uri", "ja3", "family", "verdict"])
        for f in flows:
            w.writerow(f.to_row())
    return str(path)


def run_pipeline(scenario: str, seed: int, include_decoys: bool = True,
                 thresholds: dict | None = None) -> PipelineResult:
    """Simulate → detect → zero-trust. Deterministic for a given (scenario, seed)."""
    assert_safe()  # review gate: hard-fail if any network import ever sneaks in

    cfg = _variant_cfg(scenario, include_decoys)
    res = TrafficGen(cfg, seed=seed).run()
    findings, counts = run_all(res.flows, thresholds)
    ztn = evaluate_ztn(res.flows, findings)

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    seed_tag = f"{scenario}_{seed}" + ("" if include_decoys else "_nodecoys")
    paths = {
        "pcap": res.pcap.path,
        "conn_log": _write_conn_log(res.flows, ARTIFACT_DIR / f"conn_{seed_tag}.log"),
        "eve_json": _write_eve_json(res.flows, ARTIFACT_DIR / f"eve_{seed_tag}.json"),
        "flows_csv": _write_flows_csv(res.flows, ARTIFACT_DIR / f"flows_{seed_tag}.csv"),
        "ztn_audit": write_ztn_audit(str(ARTIFACT_DIR / f"ztn_{seed_tag}.json"),
                                     ztn, scenario, seed),
    }
    return PipelineResult(
        scenario=scenario, seed=seed, flows=res.flows, findings=findings, ztn=ztn,
        verdict_counts=counts, pcap_info=res.pcap, artifact_paths=paths,
    )
