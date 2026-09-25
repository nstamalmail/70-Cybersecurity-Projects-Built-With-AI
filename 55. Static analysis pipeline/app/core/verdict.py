"""Weighted verdict engine.

Implements the indicator/weight table from the architecture document and emits
a full rationale so an analyst can see exactly how a score was reached.  The
analyst can override the verdict; overrides are recorded for audit.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

from app.core.ioc import is_noise

# Registry paths that actually mean "autostart" rather than "this binary reads a setting".
PERSISTENCE_KEY_RE = re.compile(
    r"(?i)(?:currentversion\\(?:run|runonce|runservices)|policies\\explorer\\run|"
    r"\\services\\|winlogon|appinit_dlls|image file execution options|userinit|bootexecute|"
    r"startupapproved|schedule\\taskcache)"
)

MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_CLEAN = "LIKELY CLEAN"


@dataclass
class Verdict:
    verdict: str
    score: int
    raw_score: int
    rationale: list[dict] = field(default_factory=list)
    overridden: bool = False
    override_note: str = ""
    override_analyst: str = ""
    override_at: str = ""

    def to_rows(self) -> list[list]:
        return [
            [
                r.get("indicator", ""),
                f"{r.get('weight', 0):+d}" if r.get("weight") else "",
                r.get("source", ""),
                r.get("note", ""),
            ]
            for r in self.rationale
        ]


def _add(rationale: list[dict], indicator: str, weight: int, source: str, note: str = "") -> None:
    if weight:
        rationale.append(
            {"indicator": indicator, "weight": weight, "source": source, "note": note}
        )


def compute_verdict(
    *,
    intel: dict | None = None,
    pe_info: dict | None = None,
    anomalies: list[dict] | None = None,
    capability_hits: list[dict] | None = None,
    string_stats: dict | None = None,
    interesting_strings: list[dict] | None = None,
    keywords: dict[str, list[str]] | None = None,
    signed: bool | None = None,
    packer_hints: list[str] | None = None,
    string_only: bool = False,
) -> Verdict:
    """Score the collected indicators and return a :class:`Verdict`."""
    rationale: list[dict] = []
    intel = intel or {}
    pe_info = pe_info or {}
    anomalies = anomalies or []
    capability_hits = capability_hits or []
    string_stats = string_stats or {}
    interesting_strings = interesting_strings or []
    keywords = keywords or {}
    packer_hints = packer_hints or []

    # ---------------------------------------------------------------- intel
    positives = int(intel.get("positives", 0) or 0)
    if positives > 10:
        _add(
            rationale,
            f"Threat intel detection ratio {intel.get('detection_ratio', '') or positives} (>10 engines)",
            40,
            "threat intel",
            "Multiple engines flag the sample hash.",
        )
    elif positives > 0:
        _add(
            rationale,
            f"Threat intel detection ratio {intel.get('detection_ratio', '') or positives} (1-10 engines)",
            20,
            "threat intel",
            "Low-volume detections; could be a PUP or a false positive.",
        )
    if intel.get("families"):
        _add(
            rationale,
            "Known malware family: " + ", ".join(intel["families"][:3]),
            30,
            "threat intel",
            "A named family strongly raises confidence.",
        )
    if intel.get("status") == "ok" and positives == 0 and intel.get("sources_queried"):
        _add(
            rationale,
            "No detections from queried intel sources",
            -30,
            "threat intel",
            "Reputation is clean across the sources that answered.",
        )
    if intel.get("status") == "disabled":
        _add(
            rationale,
            "Threat intel unavailable (offline mode)",
            0,
            "threat intel",
            "No reputation contribution - score reflects static evidence only.",
        )

    # ------------------------------------------------------------------- PE
    for sec in pe_info.get("sections") or []:
        if sec.get("raw_size") and float(sec.get("entropy", 0)) > 7.0:
            _add(
                rationale,
                f"High section entropy: {sec['name']} = {sec['entropy']:.2f}",
                15,
                "PE parser",
                "Entropy > 7.0 indicates packing or encryption.",
            )
    if any(a.get("id") == "wx-section" for a in anomalies):
        wx = [s["name"] for s in (pe_info.get("sections") or []) if s.get("wx")]
        _add(
            rationale,
            "Writable + executable section" + (f": {', '.join(wx)}" if wx else ""),
            10,
            "PE parser",
            "Self-modifying / unpacking stubs.",
        )
    if any(a.get("id") in ("entrypoint-outside-text",) for a in anomalies):
        _add(
            rationale,
            f"Entry point outside .text ({pe_info.get('entry_section', '?')})",
            10,
            "PE parser",
            "Packer stub or patched binary.",
        )
    if capability_hits:
        worst = max(h["weight"] for h in capability_hits)
        capabilities = sorted({h["capability"] for h in capability_hits})
        weight = 15 if worst >= 10 else 8
        _add(
            rationale,
            f"Suspicious imports ({len(capability_hits)} APIs: {', '.join(capabilities[:4])})",
            weight,
            "PE parser",
            "Imports map to high-risk capabilities.",
        )
    if packer_hints:
        _add(
            rationale,
            "Packer detected: " + ", ".join(sorted(set(packer_hints))),
            5,
            "PE parser",
            "Packer signatures in section names.",
        )
    for anomaly in anomalies:
        if anomaly.get("id") in ("large-overlay", "minimal-imports", "future-timestamp"):
            _add(
                rationale,
                anomaly.get("title", ""),
                5,
                "PE parser",
                anomaly.get("detail", ""),
            )
    if signed is True:
        _add(rationale, "Digitally signed by a trusted publisher", -20, "PE parser")
    elif signed is False:
        _add(
            rationale,
            "Not digitally signed",
            5,
            "PE parser",
            "Unsigned binaries are common but reduce confidence.",
        )

    # -------------------------------------------------------------- strings
    if string_stats:
        # Vendor/OS strings (microsoft.com, scheme URIs, system DLLs) are noise:
        # they are excluded here exactly as they are from the compiled IOC list.
        c2_like = [
            s for s in interesting_strings
            if s.get("classification") in ("url", "ipv4", "domain", "tor_address")
            and not is_noise(s.get("value", ""))
        ]
        commands = [s for s in interesting_strings if s.get("classification") == "command"]
        registry = [
            s for s in interesting_strings
            if s.get("classification") == "registry"
            and PERSISTENCE_KEY_RE.search(s.get("value", ""))
        ]
        if c2_like:
            _add(
                rationale,
                f"Network indicators in strings ({len(c2_like)} URLs/IPs/domains)",
                10,
                "string extractor",
                "Hard-coded endpoints are typical of C2 or downloaders.",
            )
        if commands:
            _add(
                rationale,
                f"Command execution strings ({len(commands)})",
                8,
                "string extractor",
                "Shell/CLI invocations embedded in the binary.",
            )
        if registry:
            _add(
                rationale,
                f"Autostart registry paths in strings ({len(registry)})",
                5,
                "string extractor",
                "Run/RunOnce/Services/Winlogon style keys indicate persistence.",
            )
    for group, hits in (keywords or {}).items():
        if hits and group in ("ransomware", "credential theft", "c2", "evasion", "lateral movement"):
            weight = 12 if group in ("ransomware", "credential theft") else 8
            _add(
                rationale,
                f"{group} keywords in strings ({len(hits)})",
                weight,
                "string extractor",
                "e.g. " + "; ".join(h[:60] for h in hits[:2]),
            )
    if string_only:
        _add(
            rationale,
            "Strings-only analysis (no PE header available)",
            0,
            "pipeline",
            "Header-derived heuristics were skipped for this input type.",
        )

    raw_score = sum(r["weight"] for r in rationale)
    score = max(0, min(100, raw_score))
    if score >= MALICIOUS_THRESHOLD:
        verdict = VERDICT_MALICIOUS
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CLEAN
    return Verdict(verdict=verdict, score=score, raw_score=raw_score, rationale=rationale)


def apply_override(base: Verdict, verdict: str, justification: str, analyst: str) -> Verdict:
    base.verdict = verdict
    base.overridden = True
    base.override_note = justification
    base.override_analyst = analyst
    base.override_at = _dt.datetime.now().isoformat(timespec="seconds")
    return base
