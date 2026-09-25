"""Detection engine — nine transparent, pure-function rules (D1–D9).

Every rule maps ``list[FlowRecord] -> list[Finding]`` with human-readable
evidence. Nothing is hidden: thresholds are plain numbers the GUI exposes.

Scoring model
-------------
Each finding carries a score; a flow's verdict is driven by the strongest
finding that covers it:
    score >= 6  -> malicious
    score >= 3  -> suspicious
    else        -> clean
D1 (SNI/Host disjunction) is special: *any* hit is malicious — it is the
domain-fronting signature itself, not a weak correlate.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean, pstdev

from src.simulator.encoders import shannon_entropy
from src.simulator.flows import FlowRecord
from src.simulator.scenario import BROWSER_JA3

DEFAULT_THRESHOLDS: dict[str, float] = {
    "d2_cv_max": 0.15,       # max coefficient of variation of inter-arrival times
    "d2_min_events": 8,      # min flows in a group to judge periodicity
    "d2_max_mean_iat": 600,  # ignore slower-than-10-min rhythms
    "d4_entropy": 7.2,       # bits/byte that counts as "high" for a body window
    "d4_min_windows": 2,
    "d4_min_body": 512,      # don't entropy-judge tiny bodies
    "d5_min_len": 20,        # DGA: hostname length
    "d5_entropy": 0.85,      # DGA: char-class entropy (3-class max is 1.585; >0.85 == well-mixed)
    "d6_min_dsts": 4,        # rare-SNI pivot fan-out
    "d7_uri_len": 120,       # over-long URI
    "d8_max_ttl": 64,        # unusual (non-client-stack) TTL cohort
    "d8_min_dsts": 3,
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    score: int
    evidence: str
    explanation: str
    flow_indices: list[int] = field(default_factory=list)
    group_key: str = ""

    def to_row(self) -> tuple:
        return (self.rule_id, self.severity, self.score, self.group_key or "-",
                self.evidence if len(self.evidence) < 90 else self.evidence[:87] + "…")


# --------------------------------------------------------------------- helpers
def _windowed_entropy(body: bytes, window: int = 256, step: int = 256) -> list[float]:
    return [shannon_entropy(body[i:i + window]) for i in range(0, len(body) - window + 1, step)]


def _char_class_entropy(name: str) -> float:
    """Entropy over the character-class distribution (lower/digit/other)."""
    import math
    if not name:
        return 0.0
    classes = {"lower": 0, "digit": 0, "other": 0}
    for ch in name:
        if ch.islower():
            classes["lower"] += 1
        elif ch.isdigit():
            classes["digit"] += 1
        else:
            classes["other"] += 1
    n = len(name)
    ent = 0.0
    for c in classes.values():
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# ----------------------------------------------------------------- the rules
def d1_sni_host_mismatch(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """The domain-fronting signature: SNI (sensor-visible) != Host (CDN-visible)."""
    hits = [i for i, f in enumerate(flows)
            if f.app == "http" and f.sni and f.host and f.sni != f.host]
    if not hits:
        return []
    sample = flows[hits[0]]
    return [Finding(
        rule_id="D1",
        title="SNI/Host disjunction (domain fronting signature)",
        severity="critical",
        score=10,
        group_key=f"{sample.sni} → {sample.host}",
        evidence=f"{len(hits)} flows where TLS SNI ≠ HTTP Host "
                 f"(e.g. sni={sample.sni} host={sample.host})",
        explanation=("TLS ClientHello carries one name; the HTTP request inside the "
                     "tunnel carries another. The front domain passes CDN routing "
                     "while the concealed origin is only visible to the CDN — a "
                     "sensor sees the mismatch, not the origin."),
        flow_indices=hits,
    )]


def d2_beacon_periodicity(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Regular callback rhythm — protocol manners survive encryption.

    Grouped by (source, TLS fingerprint): an implant's fingerprint is the stable
    key even when it rotates CDN edges — edge rotation must not hide rhythm.
    """
    groups: dict[tuple, list[int]] = defaultdict(list)
    for i, f in enumerate(flows):
        if f.app == "http" and f.family != "ntp":  # NTP judged separately by D9
            groups[(f.src, f.ja3 or "?")].append(i)
    out: list[Finding] = []
    for key, idxs in sorted(groups.items()):
        if len(idxs) < th["d2_min_events"]:
            continue
        ts = sorted(flows[i].ts for i in idxs)
        iats = [b - a for a, b in zip(ts, ts[1:])]
        mu = mean(iats)
        if mu <= 0 or mu > th["d2_max_mean_iat"]:
            continue
        cv = pstdev(iats) / mu
        if cv <= th["d2_cv_max"]:
            out.append(Finding(
                rule_id="D2",
                title="Beacon periodicity",
                severity="high",
                score=6,
                group_key=f"{key[0]} [{key[1][:24]}]",
                evidence=f"{len(idxs)} flows, mean interval {mu:.1f}s, CV {cv:.3f} "
                         f"(≤ {th['d2_cv_max']})",
                explanation=("Inter-arrival times are far too regular for human "
                             "traffic. Machine rhythm survives encryption because "
                             "timing is metadata, not content."),
                flow_indices=idxs,
            ))
    return out


def d3_ja3_cluster(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """One tool ⇒ one ClientHello shape ⇒ same fingerprint across many destinations."""
    groups: dict[str, set[str]] = defaultdict(set)
    idxs_by_ja3: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(flows):
        if f.app == "http" and f.ja3:
            groups[f.ja3].add(f.dst)
            idxs_by_ja3[f.ja3].append(i)
    out: list[Finding] = []
    for ja3, dsts in sorted(groups.items()):
        if ja3 == BROWSER_JA3 or len(dsts) < th["d6_min_dsts"]:
            continue
        out.append(Finding(
            rule_id="D3",
            title="TLS fingerprint cluster (JA3-style)",
            severity="medium",
            score=4,
            group_key=ja3,
            evidence=f"fingerprint {ja3} used toward {len(dsts)} distinct destinations",
            explanation=("The allow-listed browser fingerprint is one cluster; an "
                         "implant's fingerprint appearing on many destinations is a "
                         "second cluster. Destination diversity + fingerprint "
                         "constancy is the anomaly."),
            flow_indices=idxs_by_ja3[ja3],
        ))
    return out


def d4_high_entropy_body(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Encrypted/layered payloads look uniformly random; human content does not."""
    out: list[Finding] = []
    for i, f in enumerate(flows):
        if f.app != "http" or len(f.body) < th["d4_min_body"]:
            continue
        windows = _windowed_entropy(f.body)
        hot = [w for w in windows if w > th["d4_entropy"]]
        if len(hot) >= th["d4_min_windows"]:
            out.append(Finding(
                rule_id="D4",
                title="High-entropy payload body",
                severity="medium",
                score=4,
                group_key=f"{f.src} → {f.host or f.sni}",
                evidence=f"{len(hot)}/{len(windows)} windows above {th['d4_entropy']} "
                         f"bits/byte (body {len(f.body)}B, max {max(windows):.2f})",
                explanation=("Compressed or layered-encoded content saturates the "
                             "byte-frequency distribution near 8 bits/byte. Normal "
                             "markup and text sit far lower. High entropy + beacon "
                             "rhythm (D2) is a strong exfil/check-in signature."),
                flow_indices=[i],
            ))
    return out


def d5_dga_heuristic(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Algorithmic domains: long, character-class-mixed, structureless names."""
    per_host: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(flows):
        if f.app == "dns" and f.host:
            per_host[f.host].append(i)
    out: list[Finding] = []
    for host, idxs in sorted(per_host.items()):
        labels = host.split(".")
        name = labels[0]
        score = 0
        if len(name) >= th["d5_min_len"]:
            score += 1
        ent = _char_class_entropy(name)
        if ent > th["d5_entropy"]:
            score += 1
        digits = sum(ch.isdigit() for ch in name)
        if digits >= 3 and digits / max(len(name), 1) > 0.15:
            score += 1
        if score >= 2:
            out.append(Finding(
                rule_id="D5",
                title="DGA-like hostname",
                severity="medium",
                score=3,
                group_key=host,
                evidence=f"label len {len(name)}, class entropy {ent:.2f}, "
                         f"digits {digits} (score {score}/3)",
                explanation=("Domain Generation Algorithms produce long, mixed-class, "
                             "vowel-less names. No single feature is proof — the "
                             "scored combination keeps ordinary names out."),
                flow_indices=idxs,
            ))
    return out


def d6_rare_sni_pivot(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """One SNI fanning out to many destinations — CDN abuse / fronting geometry."""
    sni_dsts: dict[str, set[str]] = defaultdict(set)
    sni_idxs: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(flows):
        if f.app == "http" and f.sni:
            sni_dsts[f.sni].add(f.dst)
            sni_idxs[f.sni].append(i)
    out: list[Finding] = []
    for sni, dsts in sorted(sni_dsts.items()):
        idxs = sni_idxs[sni]
        non_browser = any(flows[i].ja3 != BROWSER_JA3 for i in idxs)
        if len(dsts) >= th["d6_min_dsts"] and non_browser:
            out.append(Finding(
                rule_id="D6",
                title="Rare-SNI multi-destination pivot",
                severity="medium",
                score=3,
                group_key=sni,
                evidence=f"SNI {sni} contacted {len(dsts)} distinct destinations "
                         f"with a non-browser fingerprint",
                explanation=("Popular domains fan out because many users hit many "
                             "edges. A rare name fanning out from one implant "
                             "fingerprint is different geometry: it suggests tunnel "
                             "setup or fronting rotation."),
                flow_indices=idxs,
            ))
    return out


def d7_uri_anomaly(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Over-long, over-encoded requests — layered encoding leaves wrapper bulk."""
    out: list[Finding] = []
    for i, f in enumerate(flows):
        if f.app != "http":
            continue
        long_uri = len(f.uri) > th["d7_uri_len"]
        layered = len(f.encoding_layers) >= 2
        if long_uri or layered:
            out.append(Finding(
                rule_id="D7",
                title="URI anomaly (over-long / layered-encoded)",
                severity="low",
                score=3,
                group_key=f"{f.src} → {f.host or f.sni}",
                evidence=f"uri length {len(f.uri)} (>{th['d7_uri_len']}), "
                         f"encoding layers {f.encoding_layers or 'none'}",
                explanation=("Each encoding layer inflates the payload (Base64 ×1.37, "
                             "XOR none, wrapping compounds). Wrapper bulk in a URI is "
                             "the visible cost of hiding content."),
                flow_indices=[i],
            ))
    return out


def d8_ttl_cohort(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Implants built on odd stacks betray shared TTL / IP-ID stride artifacts."""
    groups: dict[int, set[str]] = defaultdict(set)
    idxs_by_ttl: dict[int, list[int]] = defaultdict(list)
    for i, f in enumerate(flows):
        if f.app == "http":
            groups[f.ttl].add(f.dst)
            idxs_by_ttl[f.ttl].append(i)
    out: list[Finding] = []
    for ttl, dsts in sorted(groups.items()):
        if ttl <= th["d8_max_ttl"] and len(dsts) >= th["d8_min_dsts"]:
            out.append(Finding(
                rule_id="D8",
                title="Unusual TTL cohort (shared generator)",
                severity="low",
                score=2,
                group_key=f"ttl={ttl}",
                evidence=f"TTL {ttl} on flows toward {len(dsts)} destinations",
                explanation=("Workstation OSes start TTL at 125–128; alternate stacks "
                             "often start at 57–64. A cohort of low, identical TTLs "
                             "across destinations fingerprints one tool, not one host."),
                flow_indices=idxs_by_ttl[ttl],
            ))
    return out


def d9_decoy_discrimination(flows: list[FlowRecord], th: dict) -> list[Finding]:
    """Negative control: benign NTP rhythm must NOT fire D2-style alarms."""
    groups: dict[tuple, list[float]] = defaultdict(list)
    for f in flows:
        if f.app == "ntp":
            groups[(f.src, f.dst)].append(f.ts)
    out: list[Finding] = []
    false_fires = 0
    for key, ts in sorted(groups.items()):
        if len(ts) < th["d2_min_events"]:
            continue
        ts = sorted(ts)
        iats = [b - a for a, b in zip(ts, ts[1:])]
        mu = mean(iats)
        cv = pstdev(iats) / mu if mu > 0 else 1.0
        if cv <= th["d2_cv_max"] and mu <= th["d2_max_mean_iat"]:
            false_fires += 1
    out.append(Finding(
        rule_id="D9",
        title="Decoy discrimination (negative control)",
        severity="info" if false_fires == 0 else "high",
        score=0 if false_fires == 0 else 5,
        group_key="ntp-vs-beacon",
        evidence=(f"{false_fires} benign NTP group(s) tripped the periodicity rule"
                  if false_fires else
                  "all benign NTP groups correctly stayed below periodicity threshold"),
        explanation=("Rhythm alone must not equal malice: NTP sync is perfectly "
                     "periodic and perfectly benign. A beacon detector needs the "
                     "TLS/context corroboration (D3/D6/D8) to bifurcate the two."),
        flow_indices=[],
    ))
    return out


RULES = [d1_sni_host_mismatch, d2_beacon_periodicity, d3_ja3_cluster,
         d4_high_entropy_body, d5_dga_heuristic, d6_rare_sni_pivot,
         d7_uri_anomaly, d8_ttl_cohort, d9_decoy_discrimination]

RULE_METADATA = [
    ("D1", "SNI/Host disjunction", "critical", "Domain-fronting signature: encrypted tunnel to front domain carries HTTP for a different host."),
    ("D2", "Beacon periodicity", "high", "Low-variance callback intervals — machine rhythm in arrival-time metadata."),
    ("D3", "TLS fingerprint cluster", "medium", "One ClientHello shape reused across many destinations (implant tooling)."),
    ("D4", "High-entropy body", "medium", "Payload windows saturating byte entropy — layered/encrypted content."),
    ("D5", "DGA-like hostname", "medium", "Long, class-mixed, structureless domain labels."),
    ("D6", "Rare-SNI pivot", "medium", "One rare SNI fanning out to many destinations with non-browser fingerprints."),
    ("D7", "URI anomaly", "low", "Over-long or layered-encoded request URIs — wrapper bulk."),
    ("D8", "Unusual TTL cohort", "low", "Identical non-standard TTLs across destinations — shared generator."),
    ("D9", "Decoy discrimination", "info", "Negative control: benign NTP rhythm must stay quiet."),
]


def assign_verdicts(flows: list[FlowRecord], findings: list[Finding]) -> dict[str, int]:
    """Fold findings into per-flow verdicts. Returns verdict counts."""
    scores: dict[int, int] = {}
    d1_flows: set[int] = set()
    for f in findings:
        for i in f.flow_indices:
            scores[i] = max(scores.get(i, 0), f.score)
            if f.rule_id == "D1":
                d1_flows.add(i)
    counts = {"clean": 0, "suspicious": 0, "malicious": 0}
    for i, flow in enumerate(flows):
        if i in d1_flows or scores.get(i, 0) >= 6:
            flow.verdict = "malicious"
        elif scores.get(i, 0) >= 3:
            flow.verdict = "suspicious"
        else:
            flow.verdict = "clean"
        counts[flow.verdict] += 1
    return counts


def run_all(flows: list[FlowRecord], thresholds: dict | None = None) -> tuple[list[Finding], dict[str, int]]:
    """Execute D1–D9 and assign verdicts. Pure — safe to call from tests."""
    th = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        th.update(thresholds)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(flows, th))
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id, f.group_key))
    counts = assign_verdicts(flows, findings)
    return findings, counts
