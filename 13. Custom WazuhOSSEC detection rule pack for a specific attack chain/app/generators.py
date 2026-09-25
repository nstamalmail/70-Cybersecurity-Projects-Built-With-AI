"""XML rendering and pack assembly for the rule pack builder.

This is the ONLY module that produces XML strings. Everything else works
against the domain model (models.py), so the generated files are always
consistent with what the user sees in the GUI.
"""

from __future__ import annotations

import csv
import io
import os
import zipfile
from xml.etree import ElementTree as ET

from .models import (
    AttackChain,
    ConditionType,
    CustomDecoder,
    DetectionRule,
    PackOptions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _xml_decl() -> str:
    return '<?xml version="1.0" encoding="ISO-8859-1"?>\n'


def _tostring(root: ET.Element) -> str:
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    return _xml_decl() + body + "\n"


def _comment(text: str) -> ET.Element:
    # XML comments may not contain "--"; sanitize to stay well-formed.
    return ET.Comment(text.replace("--", "- -"))


def _condition_children(rule: DetectionRule, root: ET.Element) -> None:
    """Attach the match/regex/field condition element(s) to *root*."""
    cond = rule.condition
    if cond == ConditionType.MATCH:
        el = ET.SubElement(root, "match")
        el.text = rule.pattern
    elif cond == ConditionType.REGEX:
        el = ET.SubElement(root, "regex", {"type": "pcre2"})
        el.text = rule.pattern
    elif cond == ConditionType.FIELD:
        el = ET.SubElement(root, "field", {"name": rule.field_name, "type": "pcre2"})
        el.text = rule.pattern
    elif cond == ConditionType.FREQUENCY:
        # Frequency rules need a base condition (match or field) plus counters.
        if rule.field_name:
            el = ET.SubElement(root, "field", {"name": rule.field_name, "type": "pcre2"})
        else:
            el = ET.SubElement(root, "match")
        el.text = rule.pattern
        ET.SubElement(root, "frequency").text = str(rule.frequency)
        ET.SubElement(root, "timeframe").text = str(rule.timeframe)


def _render_rule(rule: DetectionRule, group_name: str) -> ET.Element:
    attrs = {
        "id": str(rule.rule_id),
        "level": str(rule.level),
    }
    if rule.groups:
        attrs["group"] = ",".join(rule.groups)

    r = ET.Element("rule", attrs)
    ET.SubElement(r, "decoded_as").text = rule.decoder
    _condition_children(rule, r)
    ET.SubElement(r, "description").text = rule.description

    if rule.has_mitre():
        mitre = ET.SubElement(r, "mitre")
        if rule.mitre_id:
            ET.SubElement(mitre, "id").text = rule.mitre_id
        if rule.mitre_tactic:
            ET.SubElement(mitre, "tactic").text = rule.mitre_tactic
    return r


# ---------------------------------------------------------------------------
# Public render functions
# ---------------------------------------------------------------------------

def render_rules_xml(chain: AttackChain, options: PackOptions) -> str:
    """Render the whole chain as a single <group>-wrapped rules file."""
    root = ET.Element("group", {"name": options.group_name})

    for step in chain.steps:
        # A comment per step keeps the narrative readable in the file itself.
        root.append(_comment(f" === {step.name} === "))
        for tech in step.techniques:
            root.append(_comment(f" ==> {tech.technique_id or '?'}: {tech.name}"))
            for rule in tech.rules:
                root.append(_render_rule(rule, options.group_name))

    # The group element itself must be the last attribute-carrying child;
    # comments are fine anywhere.
    return _tostring(root)


def render_decoders_xml(decoders: list[CustomDecoder]) -> str:
    root = ET.Element("decoder_list")
    for dec in decoders:
        d = ET.SubElement(root, "decoder", {"name": dec.name})
        ET.SubElement(d, "prematch").text = dec.prematch
        ET.SubElement(d, "regex").text = dec.regex
        ET.SubElement(d, "order").text = dec.order
    return _tostring(root)


def render_ossec_snippet(decoder_filename: str, rule_filename: str) -> str:
    """Snippet to paste into ossec.conf so the manager loads the pack."""
    return (
        "<!-- Rule pack: paste into /var/ossec/etc/ossec.conf (inside <ossec_config>) -->\n"
        f'<ossec_config>\n'
        f'  <decoder_dir>etc/decoders</decoder_dir>\n'
        f'  <rule_dir>etc/rules</rule_dir>\n'
        f'  <include>{decoder_filename}</include>\n'
        f'  <include>{rule_filename}</include>\n'
        f'</ossec_config>\n'
    )


def pack_summary(chain: AttackChain, decoders: list[CustomDecoder]) -> dict[str, int]:
    return {
        "steps": len(chain.steps),
        "techniques": len(chain.all_techniques()),
        "rules": chain.count_rules(),
        "decoders": len(decoders),
        "mitre_mapped": sum(1 for r in chain.all_rules() if r.has_mitre()),
    }


# ---------------------------------------------------------------------------
# README / inventory
# ---------------------------------------------------------------------------

def render_readme(chain: AttackChain, options: PackOptions) -> str:
    lines: list[str] = []
    lines.append(f"# {chain.name} — Wazuh/OSSEC Rule Pack")
    lines.append("")
    if chain.description:
        lines.append(chain.description)
        lines.append("")
    lines.append("## Contents")
    lines.append("")
    lines.append("| File | Purpose |")
    lines.append("|---|---|")
    lines.append(f"| `{options.rule_filename}` | Detection rules (group `{options.group_name}`) |")
    lines.append(f"| `{options.decoder_filename}` | Custom decoders for non-standard logs |")
    lines.append("| `ossec.conf.snippet` | Include lines for `ossec.conf` |")
    lines.append("| `rules.csv` | Machine-readable rule inventory |")
    lines.append("")
    lines.append("## Deployment (Wazuh Manager / OSSEC)")
    lines.append("")
    lines.append("1. Copy the XML files to the manager:")
    lines.append("")
    lines.append("   ```bash")
    lines.append(f"   sudo cp {options.rule_filename} {options.decoder_filename} /var/ossec/etc/rules/")
    lines.append("   sudo chown root:wazuh /var/ossec/etc/rules/*.xml")
    lines.append("   ```")
    lines.append("")
    lines.append("2. Add the includes to `/var/ossec/etc/ossec.conf` (see `ossec.conf.snippet`).")
    lines.append("")
    lines.append("3. Validate and reload:")
    lines.append("")
    lines.append("   ```bash")
    lines.append("   sudo /var/ossec/bin/verify_rules /var/ossec/etc/rules/*.xml")
    lines.append("   sudo systemctl restart wazuh-manager")
    lines.append("   ```")
    lines.append("")
    lines.append("4. Test a sample event with the real decoder:")
    lines.append("")
    lines.append("   ```bash")
    lines.append("   echo '<paste a sample log line>' | sudo /var/ossec/bin/wazuh-logtest")
    lines.append("   ```")
    lines.append("")
    lines.append("## Rule inventory")
    lines.append("")
    lines.append("| Rule ID | Level | Groups | Condition | Pattern | MITRE |")
    lines.append("|---|---|---|---|---|---|")
    for rule in chain.all_rules():
        mitre = rule.mitre_id or (rule.mitre_tactic or "-")
        cond = rule.condition.value
        if rule.condition == ConditionType.FREQUENCY:
            cond = f"frequency {rule.frequency}/{rule.timeframe}s"
        lines.append(
            f"| {rule.rule_id} | {rule.level} | {rule.groups_str()} | {cond} "
            f"| `{_short(rule.pattern)}` | {mitre} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Rule IDs are assigned from the base range; keep the pack on a")
    lines.append("  dedicated manager (or merge with your local ruleset and re-validate).")
    lines.append("- Validate on a staging manager before production roll-out.")
    lines.append("")
    return "\n".join(lines)


def _short(text: str, limit: int = 60) -> str:
    text = text.replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_rules_csv(chain: AttackChain) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["rule_id", "level", "groups", "condition", "pattern", "decoder",
                     "mitre_id", "mitre_tactic", "technique", "technique_id", "step", "description"])
    for step in chain.steps:
        for tech in step.techniques:
            for rule in tech.rules:
                writer.writerow([
                    rule.rule_id, rule.level, rule.groups_str(), rule.condition.value,
                    rule.pattern, rule.decoder, rule.mitre_id, rule.mitre_tactic,
                    tech.name, tech.technique_id, step.name, rule.description,
                ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Pack assembly (zip export)
# ---------------------------------------------------------------------------

def build_pack_zip(
    chain: AttackChain,
    decoders: list[CustomDecoder],
    options: PackOptions,
    out_dir: str,
) -> str:
    """Write the pack files into *out_dir* and return the zip file path."""
    os.makedirs(out_dir, exist_ok=True)

    base = _safe_base_name(chain.name)
    zip_path = os.path.join(out_dir, f"wazuh-pack-{base}.zip")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(options.rule_filename, render_rules_xml(chain, options))
        zf.writestr(options.decoder_filename, render_decoders_xml(decoders))
        zf.writestr("ossec.conf.snippet", render_ossec_snippet(
            options.decoder_filename, options.rule_filename))
        zf.writestr("README.md", render_readme(chain, options))
        zf.writestr("rules.csv", render_rules_csv(chain))
    return zip_path


def _safe_base_name(name: str) -> str:
    keep = [c if c.isalnum() or c in "-_" else "-" for c in name.strip().lower()]
    return "".join(keep).strip("-")[:40] or "pack"