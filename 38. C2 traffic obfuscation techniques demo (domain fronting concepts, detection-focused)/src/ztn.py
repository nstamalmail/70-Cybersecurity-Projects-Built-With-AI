"""Zero-Trust Network verdicts — a safe, offline policy state machine.

Maps aggregated detection findings to ``allow | verify | deny`` per source host
and emits an audit trail. No enforcement action exists (there is no network to
enforce on); this demonstrates the *decision layer* of zero-trust egress.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from src.detections import Finding
from src.simulator.flows import FlowRecord

# Rule scores above this leave the "allow" band.
ALLOW_BAND = 2
VERIFY_BAND = 5


@dataclass
class ZtnDecision:
    src: str
    verdict: str                 # allow | verify | deny
    score: int
    rules: list[str]
    reasons: list[str]

    def to_row(self) -> tuple:
        return (self.src, self.verdict, self.score, ",".join(self.rules) or "-",
                "; ".join(self.reasons) if self.reasons else "-")


@dataclass
class ZtnReport:
    decisions: list[ZtnDecision] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    @property
    def counts(self) -> dict[str, int]:
        out = {"allow": 0, "verify": 0, "deny": 0}
        for d in self.decisions:
            out[d.verdict] += 1
        return out


def _best_score_per_src(flows: list[FlowRecord]) -> dict[str, tuple[int, set[str], list[str]]]:
    best: dict[str, tuple[int, set[str], list[str]]] = {}
    for f in flows:
        s = {"clean": 0, "suspicious": 3, "malicious": 8}[f.verdict]
        rules: set[str] = set()
        reasons: list[str] = []
        if f.verdict == "malicious":
            rules.add("D1" if (f.sni and f.host and f.sni != f.host) else "D2+")
            reasons.append(f.note or f"{f.app} to {f.dst}")
        elif f.verdict == "suspicious":
            rules.add("D3/D7" if f.encoding_layers or f.ja3 else "D2+")
            reasons.append(f.note or f"{f.app} to {f.dst}")
        cur = best.get(f.src, (0, set(), []))
        merged_reasons = cur[2] + ([reasons[0]] if reasons and reasons[0] not in cur[2] else [])
        best[f.src] = (max(cur[0], s), cur[1] | rules, merged_reasons[:5])
    return best


def evaluate_ztn(flows: list[FlowRecord], findings: list[Finding]) -> ZtnReport:
    """Fold per-flow verdicts into per-host zero-trust decisions."""
    report = ZtnReport()
    per_src = _best_score_per_src(flows)
    for src in sorted(per_src):
        score, rules, reasons = per_src[src]
        if score >= 8 or "D1" in rules:
            verdict = "deny"
        elif score > ALLOW_BAND:
            verdict = "verify"
        else:
            verdict = "allow"
        report.decisions.append(ZtnDecision(
            src=src, verdict=verdict, score=score, rules=sorted(rules), reasons=reasons,
        ))
    return report


def ztn_audit_json(report: ZtnReport, scenario: str, seed: int) -> str:
    """Serialize the audit trail (offline artifact)."""
    return json.dumps({
        "kind": "ztn_audit",
        "scenario": scenario,
        "seed": seed,
        "generated_at": report.generated_at,
        "policy": {"allow_band_max": ALLOW_BAND, "verify_band_max": VERIFY_BAND},
        "counts": report.counts,
        "decisions": [
            {
                "src": d.src, "verdict": d.verdict, "score": d.score,
                "rules": d.rules, "reasons": d.reasons,
            }
            for d in report.decisions
        ],
    }, indent=2)


def write_ztn_audit(path: str, report: ZtnReport, scenario: str, seed: int) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(ztn_audit_json(report, scenario, seed))
    return path
