"""Validation for rule packs — fail-safe export.

`validate_pack()` returns a list of issues; any ERROR blocks export in the UI.
Pure functions, no side effects, easily unit-tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from .generators import render_rules_xml, render_decoders_xml
from .models import (
    BUILTIN_DECODERS,
    MITRE_ID_RE,
    MITRE_TACTICS,
    AttackChain,
    ConditionType,
    CustomDecoder,
    DetectionRule,
    PackOptions,
)

ERROR = "ERROR"
WARNING = "WARNING"


@dataclass(frozen=True)
class Issue:
    severity: str
    message: str
    rule_id: int | None = None
    decoder: str | None = None

    def display(self) -> str:
        where = ""
        if self.rule_id is not None:
            where = f" [rule {self.rule_id}]"
        elif self.decoder is not None:
            where = f" [decoder '{self.decoder}']"
        return f"{self.severity}: {self.message}{where}"


def validate_pack(
    chain: AttackChain,
    decoders: list[CustomDecoder],
    options: PackOptions,
) -> list[Issue]:
    issues: list[Issue] = []
    seen_ids: dict[int, str] = {}
    custom_names = {d.name for d in decoders}

    for rule in chain.all_rules():
        _validate_rule(rule, options, decoders, custom_names, seen_ids, issues)

    for dec in decoders:
        _validate_decoder(dec, issues)

    # Cross-cutting checks
    if chain.count_rules() == 0:
        issues.append(Issue(ERROR, "Chain contains no rules — nothing to deploy."))
    for tech in chain.all_techniques():
        if not tech.rules:
            issues.append(Issue(
                WARNING,
                f"Technique {tech.technique_id or tech.name!r} has no rules.",
            ))

    # XML round-trip: if the renderer produces something unparseable, the
    # whole pack would fail to load on the manager — treat as fatal.
    try:
        ET.fromstring(render_rules_xml(chain, options))
    except ET.ParseError as exc:
        issues.append(Issue(ERROR, f"Generated rules XML is not well-formed: {exc}"))
    try:
        ET.fromstring(render_decoders_xml(decoders))
    except ET.ParseError as exc:
        issues.append(Issue(ERROR, f"Generated decoders XML is not well-formed: {exc}"))

    return issues


def _validate_rule(
    rule: DetectionRule,
    options: PackOptions,
    decoders: list[CustomDecoder],
    custom_names: set[str],
    seen_ids: dict[int, str],
    issues: list[Issue],
) -> None:
    rid = rule.rule_id

    if rid in seen_ids:
        issues.append(Issue(ERROR, f"Duplicate rule ID {rid} (also used by {seen_ids[rid]}).", rid))
    else:
        seen_ids[rid] = rule.description or f"rule {rid}"

    if not (0 <= rule.level <= 16):
        issues.append(Issue(ERROR, f"Level {rule.level} out of range 0-16.", rid))

    if not rule.groups:
        issues.append(Issue(ERROR, "Rule has no groups.", rid))
    elif any(not re.fullmatch(r"[A-Za-z0-9_,\- ]+", g) for g in rule.groups):
        issues.append(Issue(ERROR, "Group names contain invalid characters.", rid))

    if not rule.description.strip():
        issues.append(Issue(ERROR, "Rule has no description.", rid))

    if rule.decoder not in BUILTIN_DECODERS and rule.decoder not in custom_names:
        issues.append(Issue(ERROR, f"Decoder '{rule.decoder}' is not built-in and not defined in the pack.", rid))

    if rule.mitre_id and not MITRE_ID_RE.match(rule.mitre_id):
        issues.append(Issue(ERROR, f"MITRE id '{rule.mitre_id}' does not match T####[.###].", rid))
    if rule.mitre_tactic and rule.mitre_tactic not in MITRE_TACTICS:
        issues.append(Issue(WARNING, f"MITRE tactic '{rule.mitre_tactic}' not in the ATT&CK catalog.", rid))

    if not rule.pattern.strip():
        issues.append(Issue(ERROR, "Pattern is empty.", rid))
    else:
        try:
            re.compile(rule.pattern)
        except re.error as exc:
            issues.append(Issue(ERROR, f"Invalid pattern regex: {exc}", rid))

    if rule.condition == ConditionType.FIELD and not rule.field_name.strip():
        issues.append(Issue(ERROR, "Field condition requires a field name.", rid))

    if rule.condition == ConditionType.FREQUENCY:
        if rule.frequency <= 1:
            issues.append(Issue(ERROR, "Frequency condition needs frequency > 1.", rid))
        if rule.timeframe <= 0:
            issues.append(Issue(ERROR, "Frequency condition needs timeframe > 0 (seconds).", rid))

    if not rule.has_mitre():
        issues.append(Issue(WARNING, "Rule is not mapped to MITRE ATT&CK.", rid))


def _validate_decoder(dec: CustomDecoder, issues: list[Issue]) -> None:
    if not dec.name.strip():
        issues.append(Issue(ERROR, "Decoder has no name.", decoder=dec.name))
        return
    if not dec.prematch.strip():
        issues.append(Issue(ERROR, "Decoder has no prematch regex.", decoder=dec.name))
    if not dec.regex.strip():
        issues.append(Issue(ERROR, "Decoder has no regex.", decoder=dec.name))
    if not dec.order.strip():
        issues.append(Issue(ERROR, "Decoder has no order fields.", decoder=dec.name))
    for label, pattern in (("prematch", dec.prematch), ("regex", dec.regex)):
        if pattern.strip():
            try:
                re.compile(pattern)
            except re.error as exc:
                issues.append(Issue(ERROR, f"Invalid {label} regex: {exc}", decoder=dec.name))