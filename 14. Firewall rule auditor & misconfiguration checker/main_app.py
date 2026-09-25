"""
Firewall Rule Auditor & Misconfiguration Checker
Multi-vendor firewall configuration analysis tool.
Supports Palo Alto PAN-OS XML, Check Point CSV, FortiGate CLI configs.
"""

import sys
import os
import csv
import json
import io
import re
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

from lxml import etree
from jinja2 import Template

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QLabel,
    QFileDialog, QTextEdit, QSplitter, QFrame, QGridLayout, QGroupBox,
    QLineEdit, QComboBox, QCheckBox, QScrollArea, QProgressBar, QMessageBox,
    QAbstractItemView
)
from PySide6.QtCore import Qt, Signal, QObject, QThread, QSize
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QBrush

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class NormalizedRule:
    rule_id: str
    vendor: str
    rule_number: int
    name: Optional[str] = None
    description: Optional[str] = None
    source_zones: list = field(default_factory=list)
    dest_zones: list = field(default_factory=list)
    source_addresses: list = field(default_factory=list)
    dest_addresses: list = field(default_factory=list)
    services: list = field(default_factory=list)
    applications: list = field(default_factory=list)
    action: str = "allow"
    logging_enabled: bool = False
    disabled: bool = False
    hit_count: Optional[int] = None
    raw: dict = field(default_factory=dict)

@dataclass
class AuditFinding:
    finding_id: str
    rule_id: str
    rule_name: str
    rule_number: int
    finding_type: str
    severity: str
    description: str
    evidence: str
    remediation: str
    compliance_refs: list = field(default_factory=list)
    vendor: str = ""

# ============================================================================
# VENDOR PARSERS
# ============================================================================

class PaloAltoParser:
    """Parse Palo Alto PAN-OS XML configuration exports."""

    VENDOR = "paloalto"

    def parse(self, content: str) -> list:
        rules = []
        try:
            root = etree.fromstring(content.encode("utf-8"))
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid PAN-OS XML: {e}")

        ns = {}
        rule_entries = root.findall(".//rulebase/security/rules/entry")
        if not rule_entries:
            rule_entries = root.findall(".//entry")

        addr_map = self._build_address_map(root)
        rule_num = 0
        for entry in rule_entries:
            rule_num += 1
            name = entry.get("name", f"Rule-{rule_num}")
            desc = self._text(entry, "description")
            src_zones = self._members(entry, "from")
            dst_zones = self._members(entry, "to")
            src_addrs = self._resolve_members(entry, "source", addr_map)
            dst_addrs = self._resolve_members(entry, "destination", addr_map)
            services = self._members(entry, "service")
            apps = self._members(entry, "application")
            action_el = entry.find("action")
            action = action_el.text.strip().lower() if action_el is not None else "allow"
            log_start = self._text(entry, "log-start") == "yes"
            log_end = self._text(entry, "log-end") == "yes"
            logging_enabled = log_start or log_end
            disabled = self._text(entry, "disabled") == "yes"

            rule = NormalizedRule(
                rule_id=f"PAN-{rule_num}",
                vendor=self.VENDOR,
                rule_number=rule_num,
                name=name,
                description=desc if desc else None,
                source_zones=src_zones,
                dest_zones=dst_zones,
                source_addresses=src_addrs,
                dest_addresses=dst_addrs,
                services=[s.lower() for s in services],
                applications=[a.lower() for a in apps],
                action=action,
                logging_enabled=logging_enabled,
                disabled=disabled,
                raw={"name": name}
            )
            rules.append(rule)
        return rules

    def _text(self, elem, tag):
        el = elem.find(tag)
        return el.text.strip() if el is not None and el.text else None

    def _members(self, elem, tag):
        el = elem.find(tag)
        if el is None:
            return []
        return [m.text.strip() for m in el.findall("member") if m.text]

    def _resolve_members(self, elem, tag, addr_map):
        members = self._members(elem, tag)
        resolved = []
        for m in members:
            if m.lower() == "any":
                resolved.append("any")
            elif m in addr_map:
                resolved.append(addr_map[m])
            else:
                resolved.append(m)
        return resolved

    def _build_address_map(self, root):
        addr_map = {}
        for entry in root.findall(".//address/entry"):
            name = entry.get("name")
            ip_el = entry.find("ip-netmask")
            if ip_el is not None and ip_el.text:
                addr_map[name] = ip_el.text.strip()
            fqdn_el = entry.find("fqdn")
            if fqdn_el is not None and fqdn_el.text:
                addr_map[name] = fqdn_el.text.strip()
        for entry in root.findall(".//address-group/entry"):
            name = entry.get("name")
            static = entry.find("static")
            if static is not None:
                members = [m.text.strip() for m in static.findall("member") if m.text]
                addr_map[name] = ", ".join(members) if members else name
        return addr_map


class CheckPointParser:
    """Parse Check Point CSV rule exports."""

    VENDOR = "checkpoint"

    def parse(self, content: str) -> list:
        rules = []
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader, 1):
            name = row.get("name", f"Rule-{idx}").strip()
            source = row.get("source", "any").strip()
            dest = row.get("destination", "any").strip()
            service = row.get("service", "any").strip()
            action_raw = row.get("action", "accept").strip().lower()
            action = "allow" if action_raw in ("accept", "allow") else "deny"
            track = row.get("track", "none").strip().lower()
            logging_enabled = track in ("log", "alert", "popup", "mail", "snmp", "syslog")
            enabled = row.get("enabled", "Yes").strip().upper() == "YES"
            comments = row.get("comments", "").strip() or None

            src_list = [s.strip() for s in source.split("/") if s.strip()] if "/" in source else [source]
            dst_list = [d.strip() for d in dest.split("/") if d.strip()] if "/" in dest else [dest]
            svc_list = [s.strip() for s in service.split("/") if s.strip()] if "/" in service else [service]

            rule = NormalizedRule(
                rule_id=f"CP-{idx}",
                vendor=self.VENDOR,
                rule_number=idx,
                name=name,
                description=comments,
                source_addresses=[s.lower() for s in src_list],
                dest_addresses=[d.lower() for d in dst_list],
                services=[s.lower() for s in svc_list],
                action=action,
                logging_enabled=logging_enabled,
                disabled=not enabled,
                raw={"track": track}
            )
            rules.append(rule)
        return rules


class FortinetParser:
    """Parse FortiGate CLI configuration files."""

    VENDOR = "fortinet"

    def parse(self, content: str) -> list:
        rules = []
        blocks = re.split(r'\bedit\s+(\d+)', content)
        for i in range(1, len(blocks), 2):
            rule_num = int(blocks[i])
            block = blocks[i + 1] if i + 1 < len(blocks) else ""
            sets = {}
            for line in block.split("\n"):
                line = line.strip()
                if line.startswith("set "):
                    parts = line[4:].split(None, 1)
                    if len(parts) == 2:
                        key = parts[0]
                        vals = parts[1].strip().strip('"').split('" "')
                        vals = [v.strip('"') for v in vals]
                        sets[key] = vals

            name = sets.get("name", [f"Policy-{rule_num}"])[0]
            src_intf = sets.get("srcintf", ["any"])
            dst_intf = sets.get("dstintf", ["any"])
            src_addr = sets.get("srcaddr", ["all"])
            dst_addr = sets.get("dstaddr", ["all"])
            services = sets.get("service", ["ALL"])
            action_raw = sets.get("action", ["accept"])[0].lower()
            action = "allow" if action_raw in ("accept", "permit") else "deny"
            log_all = "all" in [l.lower() for l in sets.get("logtraffic", ["disable"])]
            log_disable = "disable" in [l.lower() for l in sets.get("logtraffic", ["disable"])]
            logging_enabled = log_all and not log_disable
            comments = sets.get("comments", [None])[0]

            rule = NormalizedRule(
                rule_id=f"FG-{rule_num}",
                vendor=self.VENDOR,
                rule_number=rule_num,
                name=name,
                description=comments if comments else None,
                source_zones=[s.lower() for s in src_intf],
                dest_zones=[d.lower() for d in dst_intf],
                source_addresses=[s.lower() for s in src_addr],
                dest_addresses=[d.lower() for d in dst_addr],
                services=[s.lower() for s in services],
                action=action,
                logging_enabled=logging_enabled,
                raw=sets
            )
            rules.append(rule)
        return rules


# ============================================================================
# ANALYSIS ENGINES
# ============================================================================

INSECURE_SERVICES = {
    "telnet", "ftp", "tftp", "snmp", "snmptrap", "http", "rlogin",
    "rexec", "rsh", "xdmcp", "bootps", "bootpc", "netbios",
    "ms-ds-445", "ms-rdp", "vnc"
}

INSECURE_SERVICE_LABELS = {
    "telnet": "Telnet (unencrypted remote access)",
    "ftp": "FTP (unencrypted file transfer)",
    "tftp": "TFTP (unencrypted trivial file transfer)",
    "snmp": "SNMP (v1/v2c - unencrypted management)",
    "snmptrap": "SNMP Trap (v1/v2c - unencrypted)",
    "http": "HTTP (unencrypted web traffic)",
    "rlogin": "RLogin (unencrypted remote login)",
    "rexec": "RExec (unencrypted remote execution)",
    "rsh": "RSH (unencrypted remote shell)",
    "xdmcp": "XDMCP (unencrypted display manager)",
    "bootps": "BOOTP Server (unencrypted boot protocol)",
    "bootpc": "BOOTP Client (unencrypted boot protocol)",
    "netbios": "NetBIOS (unencrypted name service)",
    "ms-ds-445": "SMB/CIFS (file sharing - check encryption)",
    "ms-rdp": "RDP (remote desktop - verify NLA)",
    "vnc": "VNC (unencrypted remote desktop)",
}

COMPLIANCE_MAP = {
    "overly_permissive": [
        ("NIST SP 800-53", "AC-4", "Information Flow Enforcement"),
        ("PCI DSS v4.0", "1.2.1", "Restrict inbound/outbound traffic"),
        ("CIS Control 4", "4.3", "Secure Configuration of Network Devices"),
    ],
    "no_description": [
        ("NIST SP 800-53", "CM-2", "Baseline Configuration"),
        ("PCI DSS v4.0", "1.1.1", "Formal process for firewall changes"),
        ("CIS Control 4", "4.1", "Establish and Maintain Network Policy"),
    ],
    "no_logging": [
        ("NIST SP 800-53", "AU-2", "Event Logging"),
        ("PCI DSS v4.0", "10.2.1", "Audit logs for all system components"),
        ("CIS Control 8", "8.2", "Audit Log Management"),
    ],
    "insecure_service": [
        ("NIST SP 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
        ("PCI DSS v4.0", "4.2.1", "Strong cryptography for PAN transmission"),
        ("CIS Control 3", "3.1", "Establish and Maintain Data Protection"),
    ],
    "shadowed_rule": [
        ("NIST SP 800-53", "AC-4", "Information Flow Enforcement"),
        ("CIS Control 4", "4.3", "Secure Configuration of Network Devices"),
    ],
    "redundant_rule": [
        ("NIST SP 800-53", "CM-2", "Baseline Configuration"),
        ("CIS Control 4", "4.3", "Secure Configuration of Network Devices"),
    ],
    "disabled_rule": [
        ("NIST SP 800-53", "CM-2", "Baseline Configuration"),
        ("CIS Control 4", "4.1", "Establish and Maintain Network Policy"),
    ],
    "management_exposure": [
        ("NIST SP 800-53", "AC-17", "Remote Access"),
        ("PCI DSS v4.0", "2.2.2", "Configuration standards for system components"),
        ("CIS Control 4", "4.1", "Establish and Maintain Network Policy"),
    ],
    "implicit_deny_missing": [
        ("NIST SP 800-53", "AC-4", "Information Flow Enforcement"),
        ("PCI DSS v4.0", "1.2.1", "Restrict inbound and outbound traffic"),
        ("CIS Control 4", "4.3", "Secure Configuration of Network Devices"),
    ],
}


class BestPracticeChecker:
    """Check rules against security best practices."""

    def check(self, rules: list) -> list:
        findings = []
        for rule in rules:
            findings.extend(self._check_overly_permissive(rule))
            findings.extend(self._check_no_description(rule))
            findings.extend(self._check_no_logging(rule))
            findings.extend(self._check_insecure_services(rule))
            findings.extend(self._check_disabled(rule))
            findings.extend(self._check_management_exposure(rule))
        findings.extend(self._check_implicit_deny(rules))
        return findings

    def _finding(self, rule, ftype, severity, desc, evidence, remediation):
        refs = [f"{r[0]} {r[1]}" for r in COMPLIANCE_MAP.get(ftype, [])]
        return AuditFinding(
            finding_id=str(uuid.uuid4())[:8],
            rule_id=rule.rule_id,
            rule_name=rule.name or "Unnamed",
            rule_number=rule.rule_number,
            finding_type=ftype,
            severity=severity,
            description=desc,
            evidence=evidence,
            remediation=remediation,
            compliance_refs=refs,
            vendor=rule.vendor
        )

    def _check_overly_permissive(self, rule):
        findings = []
        if rule.action != "allow":
            return findings
        is_any_src = "any" in rule.source_addresses or len(rule.source_addresses) == 0
        is_any_dst = "any" in rule.dest_addresses or len(rule.dest_addresses) == 0
        is_any_svc = "any" in rule.services or "all" in rule.services or len(rule.services) == 0
        if is_any_src and is_any_dst and is_any_svc:
            findings.append(self._finding(
                rule, "overly_permissive", "critical",
                "Rule allows ANY source to ANY destination with ANY service",
                f"Rule '{rule.name}' (#{rule.rule_number}) matches all traffic with action=allow. "
                f"Source: any, Destination: any, Service: any",
                "Replace this rule with specific rules that define allowed source, "
                "destination, and service combinations based on business requirements."
            ))
        elif is_any_src and is_any_dst:
            findings.append(self._finding(
                rule, "overly_permissive", "high",
                "Rule allows ANY source to ANY destination (broad match)",
                f"Rule '{rule.name}' (#{rule.rule_number}) matches all source/destination "
                f"pairs. Services: {', '.join(rule.services[:5])}",
                "Restrict source and destination addresses to specific network segments "
                "that require this access."
            ))
        return findings

    def _check_no_description(self, rule):
        if rule.description:
            return []
        return [self._finding(
            rule, "no_description", "medium",
            "Rule lacks a description field",
            f"Rule '{rule.name}' (#{rule.rule_number}) has no description. "
            f"This hinders understanding of rule purpose and maintenance.",
            "Add a clear description explaining the business justification, "
            "owner, and any change ticket references for this rule."
        )]

    def _check_no_logging(self, rule):
        if rule.logging_enabled:
            return []
        severity = "high" if rule.action == "allow" else "medium"
        return [self._finding(
            rule, "no_logging", severity,
            "Logging is not enabled for this rule",
            f"Rule '{rule.name}' (#{rule.rule_number}) has action={rule.action} "
            f"but logging is disabled. No audit trail exists for matching traffic.",
            "Enable log-at-start and log-at-end for this rule to maintain "
            "visibility into traffic matching this rule."
        )]

    def _check_insecure_services(self, rule):
        findings = []
        for svc in rule.services:
            if svc in INSECURE_SERVICES:
                label = INSECURE_SERVICE_LABELS.get(svc, svc)
                findings.append(self._finding(
                    rule, "insecure_service", "high",
                    f"Insecure service detected: {svc}",
                    f"Rule '{rule.name}' (#{rule.rule_number}) permits {label}. "
                    f"This service transmits data without encryption.",
                    f"Replace {svc} with its secure equivalent (e.g., SSH instead of Telnet, "
                    f"HTTPS instead of HTTP, SFTP instead of FTP). If {svc} is required, "
                    f"ensure it runs within a segmented, trusted network."
                ))
        return findings

    def _check_disabled(self, rule):
        if not rule.disabled:
            return []
        return [self._finding(
            rule, "disabled_rule", "low",
            "Disabled rule exists in rulebase",
            f"Rule '{rule.name}' (#{rule.rule_number}) is disabled but still present. "
            f"Disabled rules clutter the rulebase and may cause confusion.",
            "If this rule is no longer needed, remove it entirely from the rulebase. "
            "Document the removal in a change log."
        )]

    def _check_management_exposure(self, rule):
        if rule.action != "allow":
            return []
        mgmt_services = {"ssh", "https", "http", "telnet", "snmp", "rdp"}
        has_mgmt = any(s in mgmt_services for s in rule.services)
        is_wide = "any" in rule.source_addresses or len(rule.source_addresses) > 3
        if has_mgmt and is_wide:
            return [self._finding(
                rule, "management_exposure", "critical",
                "Management protocol accessible from wide source range",
                f"Rule '{rule.name}' (#{rule.rule_number}) allows management services "
                f"({', '.join(rule.services[:3])}) from {len(rule.source_addresses)} source(s). "
                f"This increases attack surface for management interfaces.",
                "Restrict management access to specific admin workstations or "
                "management VLAN only. Use jump boxes for administrative access."
            )]
        return []

    def _check_implicit_deny(self, rules):
        active = [r for r in rules if not r.disabled]
        if not active:
            return []
        last = active[-1]
        is_deny = last.action in ("deny", "drop", "reject")
        is_any = ("any" in last.source_addresses and
                  "any" in last.dest_addresses and
                  ("any" in last.services or "all" in last.services))
        if is_deny and is_any:
            return []
        return [AuditFinding(
            finding_id=str(uuid.uuid4())[:8],
            rule_id="SYSTEM",
            rule_name="Rulebase",
            rule_number=0,
            finding_type="implicit_deny_missing",
            severity="critical",
            description="No implicit deny-all rule at end of rulebase",
            evidence=f"Last active rule is '{last.name}' (#{last.rule_number}) "
                     f"with action={last.action}. The rulebase does not end with "
                     f"a deny-all catch-all rule.",
            remediation="Add a final deny-all rule that matches any source, any destination, "
                       "and any service. This ensures unmatched traffic is blocked by default.",
            compliance_refs=[f"{r[0]} {r[1]}" for r in COMPLIANCE_MAP.get("implicit_deny_missing", [])],
            vendor=active[0].vendor if active else ""
        )]


class ShadowingDetector:
    """Detect shadowed rules (unreachable due to earlier matching rules)."""

    def detect(self, rules: list) -> list:
        findings = []
        active = [r for r in rules if not r.disabled]
        for i in range(len(active)):
            for j in range(i + 1, len(active)):
                if self._is_shadowed(active[i], active[j]):
                    findings.append(AuditFinding(
                        finding_id=str(uuid.uuid4())[:8],
                        rule_id=active[j].rule_id,
                        rule_name=active[j].name or "Unnamed",
                        rule_number=active[j].rule_number,
                        finding_type="shadowed_rule",
                        severity="medium",
                        description=f"Rule is shadowed by earlier rule",
                        evidence=f"Rule '{active[j].name}' (#{active[j].rule_number}) is "
                                f"shadowed by '{active[i].name}' (#{active[i].rule_number}). "
                                f"The earlier rule matches all traffic that would hit this rule.",
                        remediation="Remove the shadowed rule if it serves no purpose, or "
                                   "reorder rules so the more specific rule comes first.",
                        compliance_refs=[f"{r[0]} {r[1]}" for r in COMPLIANCE_MAP.get("shadowed_rule", [])],
                        vendor=active[j].vendor
                    ))
        return findings

    def _is_shadowed(self, earlier, later):
        if earlier.action != "allow":
            return False
        if earlier.source_addresses != ["any"] and later.source_addresses == ["any"]:
            return False
        if earlier.source_addresses == ["any"] or set(later.source_addresses).issubset(set(earlier.source_addresses)):
            pass
        else:
            return False
        if earlier.dest_addresses == ["any"] or set(later.dest_addresses).issubset(set(earlier.dest_addresses)):
            pass
        else:
            return False
        if earlier.services == ["any"] or earlier.services == ["all"]:
            pass
        elif later.services == ["any"] or later.services == ["all"]:
            return False
        elif set(later.services).issubset(set(earlier.services)):
            pass
        else:
            return False
        return True


class RedundancyDetector:
    """Detect redundant/duplicate rules."""

    def detect(self, rules: list) -> list:
        findings = []
        active = [r for r in rules if not r.disabled]
        seen = {}
        for rule in active:
            key = (
                tuple(sorted(rule.source_addresses)),
                tuple(sorted(rule.dest_addresses)),
                tuple(sorted(rule.services)),
                rule.action
            )
            if key in seen:
                findings.append(AuditFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    rule_id=rule.rule_id,
                    rule_name=rule.name or "Unnamed",
                    rule_number=rule.rule_number,
                    finding_type="redundant_rule",
                    severity="low",
                    description="Rule is redundant (duplicate of earlier rule)",
                    evidence=f"Rule '{rule.name}' (#{rule.rule_number}) has identical match "
                            f"criteria as '{seen[key].name}' (#{seen[key].rule_number}).",
                    remediation="Remove this redundant rule. Keep the earlier rule and "
                               "ensure it has the correct description.",
                    compliance_refs=[f"{r[0]} {r[1]}" for r in COMPLIANCE_MAP.get("redundant_rule", [])],
                    vendor=rule.vendor
                ))
            else:
                seen[key] = rule
        return findings


# ============================================================================
# REPORT GENERATORS
# ============================================================================

SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#4488FF",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_html_report(rules, findings, title="Firewall Audit Report"):
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    total = sum(severity_counts.values())
    compliance_score = max(0, min(100, 100 - (
        severity_counts["critical"] * 10 + severity_counts["high"] * 5 +
        severity_counts["medium"] * 2 + severity_counts["low"] * 1
    )))

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
h2 {{ color: #16213e; margin-top: 30px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
.summary-card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
.summary-card h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #666; text-transform: uppercase; }}
.summary-card .value {{ font-size: 36px; font-weight: bold; }}
.severity-critical {{ color: #FF4444; }}
.severity-high {{ color: #FF8C00; }}
.severity-medium {{ color: #B8860B; }}
.severity-low {{ color: #4488FF; }}
.score {{ background: {'#FF4444' if compliance_score < 50 else '#FF8C00' if compliance_score < 75 else '#44BB44'}; color: white; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 15px 0; }}
th {{ background: #16213e; color: white; padding: 12px 15px; text-align: left; font-size: 13px; }}
td {{ padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 13px; }}
tr:hover {{ background: #f8f9fa; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; color: white; }}
.badge-critical {{ background: #FF4444; }}
.badge-high {{ background: #FF8C00; }}
.badge-medium {{ background: #FFD700; color: #333; }}
.badge-low {{ background: #4488FF; }}
.badge-allow {{ background: #44BB44; }}
.badge-deny {{ background: #FF4444; }}
.meta {{ color: #666; font-size: 12px; margin-top: 5px; }}
.section {{ background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.compliance-ref {{ background: #e8f4fd; border-left: 3px solid #2196F3; padding: 5px 10px; margin: 3px 0; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>Firewall Rule Audit Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Rules: {len(rules)} | Total Findings: {total}</p>

<div class="summary">
<div class="summary-card score"><h3>Compliance Score</h3><div class="value">{compliance_score}%</div></div>
<div class="summary-card"><h3>Total Rules</h3><div class="value">{len(rules)}</div></div>
<div class="summary-card"><h3>Critical</h3><div class="value severity-critical">{severity_counts['critical']}</div></div>
<div class="summary-card"><h3>High</h3><div class="value severity-high">{severity_counts['high']}</div></div>
<div class="summary-card"><h3>Medium</h3><div class="value severity-medium">{severity_counts['medium']}</div></div>
<div class="summary-card"><h3>Low</h3><div class="value severity-low">{severity_counts['low']}</div></div>
</div>

<h2>Detailed Findings</h2>
<table>
<thead><tr><th>#</th><th>Rule</th><th>Type</th><th>Severity</th><th>Description</th><th>Evidence</th><th>Remediation</th><th>Compliance</th></tr></thead>
<tbody>
"""
    for i, f in enumerate(sorted_findings, 1):
        refs_html = "<br>".join(f'<span class="compliance-ref">{r}</span>' for r in f.compliance_refs)
        html += f"""<tr>
<td>{i}</td>
<td><strong>{f.rule_name}</strong><br><span class="meta">Rule #{f.rule_number} | {f.vendor.upper()}</span></td>
<td>{f.finding_type.replace('_', ' ').title()}</td>
<td><span class="badge badge-{f.severity}">{f.severity.upper()}</span></td>
<td>{f.description}</td>
<td>{f.evidence}</td>
<td>{f.remediation}</td>
<td>{refs_html}</td>
</tr>"""
    html += """</tbody></table>

<h2>Rule Inventory</h2>
<table>
<thead><tr><th>#</th><th>Name</th><th>Vendor</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Logging</th><th>Status</th></tr></thead>
<tbody>
"""
    for r in rules:
        action_class = "allow" if r.action == "allow" else "deny"
        status = "Disabled" if r.disabled else "Active"
        html += f"""<tr>
<td>{r.rule_number}</td>
<td>{r.name or 'Unnamed'}</td>
<td>{r.vendor.upper()}</td>
<td>{', '.join(r.source_addresses[:3])}</td>
<td>{', '.join(r.dest_addresses[:3])}</td>
<td>{', '.join(r.services[:3])}</td>
<td><span class="badge badge-{action_class}">{r.action.upper()}</span></td>
<td>{'Yes' if r.logging_enabled else 'No'}</td>
<td>{status}</td>
</tr>"""
    html += """</tbody></table>
<div class="meta" style="text-align:center; margin-top:30px;">
Generated by Firewall Rule Auditor v1.0.0
</div>
</div></body></html>"""
    return html


def generate_csv_report(findings):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Rule ID", "Rule Name", "Rule #", "Type", "Severity",
                     "Description", "Evidence", "Remediation", "Compliance Refs", "Vendor"])
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
        writer.writerow([
            f.finding_id, f.rule_id, f.rule_name, f.rule_number,
            f.finding_type, f.severity, f.description, f.evidence,
            f.remediation, "; ".join(f.compliance_refs), f.vendor
        ])
    return output.getvalue()


def generate_json_report(rules, findings):
    return json.dumps({
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_rules": len(rules),
            "total_findings": len(findings),
            "by_severity": {
                s: sum(1 for f in findings if f.severity == s)
                for s in ["critical", "high", "medium", "low"]
            }
        },
        "findings": [asdict(f) for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))],
        "rules": [asdict(r) for r in rules]
    }, indent=2, default=str)


# ============================================================================
# DEMO DATA GENERATOR
# ============================================================================

def generate_demo_data():
    """Generate demo rules from all three vendors."""
    rules = []
    num = 0

    demo_configs = [
        {"name": "Allow-All-Internet", "src": ["any"], "dst": ["any"], "svc": ["any"], "act": "allow", "log": True, "desc": "Temporary rule for testing"},
        {"name": "Web-Server-Access", "src": ["10.0.1.10"], "dst": ["any"], "svc": ["http", "https"], "act": "allow", "log": True, "desc": "Web server outbound"},
        {"name": "DB-Access", "src": ["10.0.4.10"], "dst": ["10.0.2.0/24"], "svc": ["oracle-tcp-1521"], "act": "allow", "log": False, "desc": "Database access"},
        {"name": "Telnet-Management", "src": ["admin-workstations"], "dst": ["any"], "svc": ["telnet"], "act": "allow", "log": False, "desc": None},
        {"name": "Legacy-SSH", "src": ["any"], "dst": ["any"], "svc": ["ssh"], "act": "allow", "log": True, "desc": "SSH to DMZ"},
        {"name": "Any-Any-Deny", "src": ["any"], "dst": ["any"], "svc": ["any"], "act": "deny", "log": True, "desc": "Implicit deny"},
        {"name": "Guest-WiFi", "src": ["192.168.100.0/24"], "dst": ["any"], "svc": ["http", "https", "dns"], "act": "allow", "log": True, "desc": "Guest internet"},
        {"name": "SNMP-Monitoring", "src": ["nms-servers"], "dst": ["any"], "svc": ["snmp", "snmptrap"], "act": "allow", "log": False, "desc": None},
        {"name": "Duplicate-Web", "src": ["10.0.1.10"], "dst": ["any"], "svc": ["http", "https"], "act": "allow", "log": True, "desc": "Duplicate web rule"},
        {"name": "Deny-Internal-RDP", "src": ["any"], "dst": ["any"], "svc": ["ms-rdp"], "act": "deny", "log": True, "desc": "Block RDP"},
        {"name": "Permissive-DNS", "src": ["any"], "dst": ["any"], "svc": ["dns"], "act": "allow", "log": True, "desc": None},
        {"name": "Disabled-Old-Rule", "src": ["legacy-servers"], "dst": ["any"], "svc": ["any"], "act": "allow", "log": False, "desc": None, "disabled": True},
        {"name": "Payment-System", "src": ["app-servers"], "dst": ["10.0.10.50"], "svc": ["tcp-8443"], "act": "allow", "log": True, "desc": "PCI payment access"},
        {"name": "HTTP-Management", "src": ["admin-workstations"], "dst": ["any"], "svc": ["http"], "act": "allow", "log": False, "desc": None},
    ]

    for i, cfg in enumerate(demo_configs, 1):
        num += 1
        rules.append(NormalizedRule(
            rule_id=f"DEMO-{num}",
            vendor=["paloalto", "checkpoint", "fortinet"][i % 3],
            rule_number=num,
            name=cfg["name"],
            description=cfg.get("desc"),
            source_addresses=cfg["src"],
            dest_addresses=cfg["dst"],
            services=cfg["svc"],
            action=cfg["act"],
            logging_enabled=cfg["log"],
            disabled=cfg.get("disabled", False),
        ))

    return rules


# ============================================================================
# GUI WIDGETS
# ============================================================================

class SeverityBadge(QWidget):
    """Custom widget displaying a colored severity badge."""

    def __init__(self, severity, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.setFixedSize(80, 24)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(SEVERITY_COLORS.get(self.severity, "#888888"))
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color))
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 4, 4)
        painter.setPen(QPen(QColor("white") if self.severity != "medium" else QColor("#333")))
        font = QFont("Arial", 9, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.severity.upper())
        painter.end()


class ComplianceHeatmapWidget(QWidget):
    """Widget showing compliance heatmap grid."""

    def __init__(self, findings, parent=None):
        super().__init__(parent)
        self.findings = findings
        self.setMinimumHeight(300)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        controls = [
            ("NIST AC-4", "Information Flow\nEnforcement"),
            ("NIST SC-7", "Boundary\nProtection"),
            ("NIST AU-2", "Event\nLogging"),
            ("NIST CM-2", "Baseline\nConfiguration"),
            ("PCI 1.2.1", "Restrict Traffic\nAccess"),
            ("PCI 1.1.1", "Formal Change\nProcess"),
            ("PCI 4.2.1", "Encryption for\nPAN"),
            ("PCI 10.2.1", "Audit Logging\nRequirements"),
            ("CIS 4.1", "Network Policy\nEstablishment"),
            ("CIS 4.3", "Secure Device\nConfiguration"),
            ("CIS 3.1", "Data Protection\nPolicy"),
            ("CIS 8.2", "Audit Log\nManagement"),
        ]

        cols = 4
        rows = (len(controls) + cols - 1) // cols
        cell_w = (self.width() - 40) // cols
        cell_h = max(80, (self.height() - 80) // rows)

        painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        painter.drawText(self.rect().adjusted(0, 10, 0, 0), Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, "Compliance Control Heatmap")
        painter.setFont(QFont("Arial", 8))

        for idx, (ctrl_id, ctrl_desc) in enumerate(controls):
            col = idx % cols
            row = idx // cols
            x = 20 + col * cell_w
            y = 50 + row * cell_h

            related_findings = []
            for f in self.findings:
                for ref in f.compliance_refs:
                    if ctrl_id.split()[1] in ref:
                        related_findings.append(f)

            has_critical = any(f.severity == "critical" for f in related_findings)
            has_high = any(f.severity == "high" for f in related_findings)
            has_medium = any(f.severity == "medium" for f in related_findings)

            if has_critical:
                bg = QColor("#FF4444")
                fg = QColor("white")
            elif has_high:
                bg = QColor("#FF8C00")
                fg = QColor("white")
            elif has_medium:
                bg = QColor("#FFD700")
                fg = QColor("#333")
            elif related_findings:
                bg = QColor("#4488FF")
                fg = QColor("white")
            else:
                bg = QColor("#44BB44")
                fg = QColor("white")

            painter.setBrush(QBrush(bg))
            painter.setPen(QPen(QColor("#ccc")))
            painter.drawRoundedRect(x + 2, y + 2, cell_w - 8, cell_h - 8, 6, 6)

            painter.setPen(QPen(fg))
            painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            painter.drawText(x + 10, y + 15, cell_w - 20, 15, Qt.AlignmentFlag.AlignCenter, ctrl_id)
            painter.setFont(QFont("Arial", 7))
            lines = ctrl_desc.split("\n")
            for li, line in enumerate(lines):
                painter.drawText(x + 10, y + 32 + li * 12, cell_w - 20, 12, Qt.AlignmentFlag.AlignCenter, line)

            if related_findings:
                painter.setFont(QFont("Arial", 8, QFont.Weight.Bold))
                count_text = f"{len(related_findings)} finding{'s' if len(related_findings) != 1 else ''}"
                painter.drawText(x + 10, y + cell_h - 20, cell_w - 20, 12, Qt.AlignmentFlag.AlignCenter, count_text)

        painter.end()


class ScoreGaugeWidget(QWidget):
    """Circular gauge widget for compliance score."""

    def __init__(self, score=0, parent=None):
        super().__init__(parent)
        self.score = score
        self.setFixedSize(180, 180)

    def set_score(self, score):
        self.score = score
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        cx, cy = self.width() // 2, self.height() // 2
        radius = min(cx, cy) - 10

        painter.setPen(QPen(QColor("#e0e0e0"), 12))
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 0, 360 * 16)

        if self.score >= 75:
            color = QColor("#44BB44")
        elif self.score >= 50:
            color = QColor("#FF8C00")
        else:
            color = QColor("#FF4444")

        span = int(self.score / 100.0 * 360 * 16)
        painter.setPen(QPen(color, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 90 * 16, -span)

        painter.setPen(QPen(QColor("#333")))
        painter.setFont(QFont("Arial", 28, QFont.Weight.Bold))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self.score}%")
        painter.setFont(QFont("Arial", 9))
        painter.drawText(cx, cy + 25, 1, 20, Qt.AlignmentFlag.AlignHCenter, "Compliance")
        painter.end()


# ============================================================================
# MAIN WINDOW
# ============================================================================

class FirewallAuditorWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Rule Auditor & Misconfiguration Checker")
        self.setMinimumSize(1200, 800)
        self.rules = []
        self.findings = []
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(5, 5, 5, 5)

        toolbar = self._create_toolbar()
        main_layout.addWidget(toolbar)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tabs.addTab(self._create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self._create_rules_tab(), "Rules")
        self.tabs.addTab(self._create_findings_tab(), "Findings")
        self.tabs.addTab(self._create_shadowing_tab(), "Shadowing")
        self.tabs.addTab(self._create_compliance_tab(), "Compliance")
        self.tabs.addTab(self._create_report_tab(), "Reports")
        self.tabs.addTab(self._create_console_tab(), "Console")

        self.statusBar().showMessage("Ready — Load a firewall configuration or click 'Load Demo Data'")

    def _create_toolbar(self):
        toolbar = QFrame()
        toolbar.setFrameShape(QFrame.Shape.StyledPanel)
        toolbar.setStyleSheet("QFrame { background: #16213e; padding: 5px; }")
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(10, 5, 10, 5)

        title = QLabel("Firewall Rule Auditor")
        title.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        layout.addStretch()

        btn_demo = QPushButton("Load Demo Data")
        btn_demo.setStyleSheet("QPushButton { background: #44BB44; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #339933; }")
        btn_demo.clicked.connect(self._load_demo)
        layout.addWidget(btn_demo)

        btn_upload = QPushButton("Upload Config File")
        btn_upload.setStyleSheet("QPushButton { background: #2196F3; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #1976D2; }")
        btn_upload.clicked.connect(self._upload_config)
        layout.addWidget(btn_upload)

        btn_paloalto = QPushButton("Palo Alto XML")
        btn_paloalto.setStyleSheet("QPushButton { background: #FF8C00; color: white; border: none; padding: 8px 12px; border-radius: 4px; } QPushButton:hover { background: #E07C00; }")
        btn_paloalto.clicked.connect(lambda: self._load_sample("paloalto"))
        layout.addWidget(btn_paloalto)

        btn_checkpoint = QPushButton("Check Point CSV")
        btn_checkpoint.setStyleSheet("QPushButton { background: #9C27B0; color: white; border: none; padding: 8px 12px; border-radius: 4px; } QPushButton:hover { background: #7B1FA2; }")
        btn_checkpoint.clicked.connect(lambda: self._load_sample("checkpoint"))
        layout.addWidget(btn_checkpoint)

        btn_fortinet = QPushButton("FortiGate CLI")
        btn_fortinet.setStyleSheet("QPushButton { background: #00BCD4; color: white; border: none; padding: 8px 12px; border-radius: 4px; } QPushButton:hover { background: #0097A7; }")
        btn_fortinet.clicked.connect(lambda: self._load_sample("fortinet"))
        layout.addWidget(btn_fortinet)

        return toolbar

    def _create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        top_row = QHBoxLayout()

        left_panel = QVBoxLayout()
        self.score_gauge = ScoreGaugeWidget()
        left_panel.addWidget(self.score_gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        left_panel.addStretch()

        self.stats_group = QGroupBox("Audit Statistics")
        self.stats_group.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }")
        stats_layout = QGridLayout(self.stats_group)
        self.stat_total_rules = QLabel("0")
        self.stat_total_rules.setStyleSheet("font-size: 24px; font-weight: bold; color: #16213e;")
        self.stat_critical = QLabel("0")
        self.stat_critical.setStyleSheet("font-size: 24px; font-weight: bold; color: #FF4444;")
        self.stat_high = QLabel("0")
        self.stat_high.setStyleSheet("font-size: 24px; font-weight: bold; color: #FF8C00;")
        self.stat_medium = QLabel("0")
        self.stat_medium.setStyleSheet("font-size: 24px; font-weight: bold; color: #B8860B;")
        self.stat_low = QLabel("0")
        self.stat_low.setStyleSheet("font-size: 24px; font-weight: bold; color: #4488FF;")
        self.stat_total_findings = QLabel("0")
        self.stat_total_findings.setStyleSheet("font-size: 24px; font-weight: bold; color: #333;")

        stats_layout.addWidget(QLabel("Total Rules:"), 0, 0)
        stats_layout.addWidget(self.stat_total_rules, 0, 1)
        stats_layout.addWidget(QLabel("Critical:"), 1, 0)
        stats_layout.addWidget(self.stat_critical, 1, 1)
        stats_layout.addWidget(QLabel("High:"), 2, 0)
        stats_layout.addWidget(self.stat_high, 2, 1)
        stats_layout.addWidget(QLabel("Medium:"), 3, 0)
        stats_layout.addWidget(self.stat_medium, 3, 1)
        stats_layout.addWidget(QLabel("Low:"), 4, 0)
        stats_layout.addWidget(self.stat_low, 4, 1)
        stats_layout.addWidget(QLabel("Total Findings:"), 5, 0)
        stats_layout.addWidget(self.stat_total_findings, 5, 1)

        left_panel.addWidget(self.stats_group)
        top_row.addLayout(left_panel, 1)

        right_panel = QVBoxLayout()
        findings_summary = QGroupBox("Findings by Severity")
        findings_summary.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }")
        fs_layout = QVBoxLayout(findings_summary)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(3)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Count", "Example"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        fs_layout.addWidget(self.findings_table)

        right_panel.addWidget(findings_summary)

        vendor_group = QGroupBox("Vendor Distribution")
        vendor_group.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }")
        vg_layout = QVBoxLayout(vendor_group)
        self.vendor_table = QTableWidget()
        self.vendor_table.setColumnCount(2)
        self.vendor_table.setHorizontalHeaderLabels(["Vendor", "Rules"])
        self.vendor_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vendor_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        vg_layout.addWidget(self.vendor_table)
        right_panel.addWidget(vendor_group)

        top_row.addLayout(right_panel, 2)
        layout.addLayout(top_row)

        self.tabs_summary = QTabWidget()
        self.tabs_summary.addTab(self._create_top_findings_widget(), "Top Findings")
        self.tabs_summary.addTab(self._create_remediation_widget(), "Remediation Priority")
        layout.addWidget(self.tabs_summary)

        return tab

    def _create_top_findings_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.top_findings_text = QTextEdit()
        self.top_findings_text.setReadOnly(True)
        self.top_findings_text.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        layout.addWidget(self.top_findings_text)
        return widget

    def _create_remediation_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.remediation_text = QTextEdit()
        self.remediation_text.setReadOnly(True)
        self.remediation_text.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        layout.addWidget(self.remediation_text)
        return widget

    def _create_rules_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Filter:"))
        self.rule_filter = QLineEdit()
        self.rule_filter.setPlaceholderText("Search rules by name, source, destination, service...")
        self.rule_filter.setStyleSheet("padding: 6px; border: 1px solid #ccc; border-radius: 4px;")
        filter_bar.addWidget(self.rule_filter)

        filter_bar.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.setStyleSheet("padding: 6px;")
        filter_bar.addWidget(self.severity_filter)

        filter_bar.addWidget(QLabel("Vendor:"))
        self.vendor_filter = QComboBox()
        self.vendor_filter.addItems(["All", "Palo Alto", "Check Point", "Fortinet"])
        self.vendor_filter.setStyleSheet("padding: 6px;")
        filter_bar.addWidget(self.vendor_filter)

        layout.addLayout(filter_bar)

        self.rule_table = QTableWidget()
        self.rule_table.setColumnCount(9)
        self.rule_table.setHorizontalHeaderLabels([
            "Rule #", "Name", "Source", "Destination", "Service",
            "Action", "Logging", "Severity", "Vendor"
        ])
        header = self.rule_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        self.rule_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rule_table.setAlternatingRowColors(True)
        self.rule_table.setStyleSheet("QTableWidget { alternate-background-color: #f8f9fa; } QTableWidget::item:selected { background: #1976D2; color: white; }")
        layout.addWidget(self.rule_table)

        return tab

    def _create_findings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.findings_detail_table = QTableWidget()
        self.findings_detail_table.setColumnCount(8)
        self.findings_detail_table.setHorizontalHeaderLabels([
            "Rule #", "Rule Name", "Type", "Severity", "Description",
            "Evidence", "Remediation", "Compliance"
        ])
        header = self.findings_detail_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.findings_detail_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings_detail_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.findings_detail_table.setAlternatingRowColors(True)
        self.findings_detail_table.setStyleSheet("QTableWidget { alternate-background-color: #f8f9fa; } QTableWidget::item:selected { background: #1976D2; color: white; }")
        layout.addWidget(self.findings_detail_table)

        return tab

    def _create_shadowing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.shadow_table = QTableWidget()
        self.shadow_table.setColumnCount(5)
        self.shadow_table.setHorizontalHeaderLabels([
            "Shadowed Rule #", "Shadowed Rule Name", "Shadowed By #",
            "Shadowed By Name", "Details"
        ])
        header = self.shadow_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.shadow_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.shadow_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.shadow_table.setAlternatingRowColors(True)
        self.shadow_table.setStyleSheet("QTableWidget { alternate-background-color: #f8f9fa; } QTableWidget::item:selected { background: #1976D2; color: white; }")
        layout.addWidget(self.shadow_table)

        info = QLabel("Shadowed rules are unreachable because an earlier rule matches all traffic that would hit them.")
        info.setStyleSheet("color: #666; font-style: italic; padding: 5px;")
        layout.addWidget(info)

        return tab

    def _create_compliance_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.compliance_heatmap = ComplianceHeatmapWidget([])
        layout.addWidget(self.compliance_heatmap)
        return tab

    def _create_report_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        export_group = QGroupBox("Export Options")
        export_group.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }")
        eg_layout = QHBoxLayout(export_group)

        btn_html = QPushButton("Export HTML Report")
        btn_html.setStyleSheet("QPushButton { background: #FF8C00; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #E07C00; }")
        btn_html.clicked.connect(lambda: self._export_report("html"))
        eg_layout.addWidget(btn_html)

        btn_json = QPushButton("Export JSON Data")
        btn_json.setStyleSheet("QPushButton { background: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #388E3C; }")
        btn_json.clicked.connect(lambda: self._export_report("json"))
        eg_layout.addWidget(btn_json)

        btn_csv = QPushButton("Export CSV Findings")
        btn_csv.setStyleSheet("QPushButton { background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #1976D2; }")
        btn_csv.clicked.connect(lambda: self._export_report("csv"))
        eg_layout.addWidget(btn_csv)

        layout.addWidget(export_group)

        preview_group = QGroupBox("Report Preview")
        preview_group.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #ccc; border-radius: 6px; margin-top: 10px; padding-top: 15px; } QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }")
        pg_layout = QVBoxLayout(preview_group)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        pg_layout.addWidget(self.report_preview)
        layout.addWidget(preview_group)

        return tab

    def _create_console_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background: #1a1a2e; color: #00ff00; font-family: Consolas, monospace; font-size: 12px;")
        layout.addWidget(self.console)
        return tab

    def _connect_signals(self):
        self.rule_filter.textChanged.connect(self._apply_filters)
        self.severity_filter.currentIndexChanged.connect(self._apply_filters)
        self.vendor_filter.currentIndexChanged.connect(self._apply_filters)

    def _log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {msg}")
        self.statusBar().showMessage(msg)

    # ----------------------------------------------------------------
    # DATA LOADING
    # ----------------------------------------------------------------

    def _load_demo(self):
        self._log("Generating demo data...")
        self.rules = generate_demo_data()
        self._log(f"Loaded {len(self.rules)} demo rules from all vendors")
        self._run_audit()

    def _upload_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Firewall Configuration", "",
            "All Supported (*.xml *.csv *.conf *.txt);;XML Files (*.xml);;CSV Files (*.csv);;Config Files (*.conf *.txt);;All Files (*)"
        )
        if not path:
            return
        self._log(f"Loading configuration: {os.path.basename(path)}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.rules = self._detect_and_parse(path, content)
            self._log(f"Parsed {len(self.rules)} rules from {os.path.basename(path)}")
            self._run_audit()
        except Exception as e:
            self._log(f"ERROR: Failed to parse file: {e}")
            QMessageBox.critical(self, "Parse Error", f"Failed to parse configuration:\n{e}")

    def _load_sample(self, vendor):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        samples = {
            "paloalto": os.path.join(script_dir, "sample_data", "sample_paloalto.xml"),
            "checkpoint": os.path.join(script_dir, "sample_data", "sample_checkpoint.csv"),
            "fortinet": os.path.join(script_dir, "sample_data", "sample_fortinet.conf"),
        }
        path = samples.get(vendor)
        if not path or not os.path.exists(path):
            self._log(f"Sample file not found: {path}")
            QMessageBox.warning(self, "File Not Found", f"Sample file not found:\n{path}")
            return
        self._log(f"Loading sample {vendor} configuration...")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.rules = self._detect_and_parse(path, content)
            self._log(f"Parsed {len(self.rules)} rules from sample {vendor} config")
            self._run_audit()
        except Exception as e:
            self._log(f"ERROR: Failed to parse sample: {e}")
            QMessageBox.critical(self, "Parse Error", f"Failed to parse sample:\n{e}")

    def _detect_and_parse(self, path, content):
        ext = os.path.splitext(path)[1].lower()
        if ext == ".xml" or content.strip().startswith("<?xml") or content.strip().startswith("<config"):
            self._log("Detected format: Palo Alto PAN-OS XML")
            return PaloAltoParser().parse(content)
        elif ext == ".csv" or ("," in content.split("\n")[0] and "rule" in content.split("\n")[0].lower()):
            self._log("Detected format: Check Point CSV")
            return CheckPointParser().parse(content)
        else:
            self._log("Detected format: FortiGate CLI config")
            return FortinetParser().parse(content)

    # ----------------------------------------------------------------
    # AUDIT ENGINE
    # ----------------------------------------------------------------

    def _run_audit(self):
        self._log("Running best-practice checks...")
        bp = BestPracticeChecker()
        self.findings = bp.check(self.rules)
        self._log(f"  Best-practice findings: {len(self.findings)}")

        self._log("Detecting shadowed rules...")
        sd = ShadowingDetector()
        shadow_findings = sd.detect(self.rules)
        self.findings.extend(shadow_findings)
        self._log(f"  Shadowed rules found: {len(shadow_findings)}")

        self._log("Detecting redundant rules...")
        rd = RedundancyDetector()
        redund_findings = rd.detect(self.rules)
        self.findings.extend(redund_findings)
        self._log(f"  Redundant rules found: {len(redund_findings)}")

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        self._log(f"Audit complete: {len(self.findings)} total findings")
        self._log(f"  Critical: {counts['critical']} | High: {counts['high']} | "
                  f"Medium: {counts['medium']} | Low: {counts['low']}")

        self._update_all_views()

    # ----------------------------------------------------------------
    # VIEW UPDATES
    # ----------------------------------------------------------------

    def _update_all_views(self):
        self._update_dashboard()
        self._update_rule_table()
        self._update_findings_table()
        self._update_shadow_table()
        self._update_compliance_heatmap()
        self._update_report_preview()

    def _update_dashboard(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        total_findings = sum(counts.values())
        score = max(0, min(100, 100 - (
            counts["critical"] * 10 + counts["high"] * 5 +
            counts["medium"] * 2 + counts["low"] * 1
        )))

        self.score_gauge.set_score(score)
        self.stat_total_rules.setText(str(len(self.rules)))
        self.stat_critical.setText(str(counts["critical"]))
        self.stat_high.setText(str(counts["high"]))
        self.stat_medium.setText(str(counts["medium"]))
        self.stat_low.setText(str(counts["low"]))
        self.stat_total_findings.setText(str(total_findings))

        self.findings_table.setRowCount(0)
        for sev in ["critical", "high", "medium", "low"]:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            example = next((f.rule_name for f in self.findings if f.severity == sev), "N/A")
            sev_item = QTableWidgetItem(sev.upper())
            sev_item.setForeground(QColor(SEVERITY_COLORS[sev]))
            sev_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.findings_table.setItem(row, 0, sev_item)
            self.findings_table.setItem(row, 1, QTableWidgetItem(str(counts[sev])))
            self.findings_table.setItem(row, 2, QTableWidgetItem(example))

        vendor_counts = {}
        for r in self.rules:
            v = r.vendor
            vendor_counts[v] = vendor_counts.get(v, 0) + 1
        self.vendor_table.setRowCount(0)
        for vendor, count in vendor_counts.items():
            row = self.vendor_table.rowCount()
            self.vendor_table.insertRow(row)
            self.vendor_table.setItem(row, 0, QTableWidgetItem(vendor.upper()))
            self.vendor_table.setItem(row, 1, QTableWidgetItem(str(count)))

        self.top_findings_text.clear()
        self.top_findings_text.append("TOP FINDINGS BY SEVERITY\n" + "=" * 50 + "\n")
        for sev in ["critical", "high", "medium", "low"]:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if sev_findings:
                self.top_findings_text.append(f"\n--- {sev.upper()} ({len(sev_findings)}) ---")
                for f in sev_findings[:5]:
                    self.top_findings_text.append(
                        f"  [{f.rule_name}] Rule #{f.rule_number}: {f.description}"
                    )

        self.remediation_text.clear()
        self.remediation_text.append("REMEDIATION PRIORITY ORDER\n" + "=" * 50 + "\n")
        priority_order = ["critical", "high", "medium", "low"]
        priority_num = 1
        for sev in priority_order:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if sev_findings:
                self.remediation_text.append(f"\n[{priority_num}. {sev.upper()} PRIORITY]")
                for f in sev_findings[:3]:
                    self.remediation_text.append(
                        f"  Fix: {f.rule_name} (Rule #{f.rule_number})\n"
                        f"  Action: {f.remediation}\n"
                    )
                priority_num += 1

    def _update_rule_table(self):
        self.rule_table.setRowCount(0)
        for rule in self.rules:
            row = self.rule_table.rowCount()
            self.rule_table.insertRow(row)

            item_num = QTableWidgetItem(str(rule.rule_number))
            item_num.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rule_table.setItem(row, 0, item_num)

            self.rule_table.setItem(row, 1, QTableWidgetItem(rule.name or "Unnamed"))

            src_text = ", ".join(rule.source_addresses[:3])
            if len(rule.source_addresses) > 3:
                src_text += f" (+{len(rule.source_addresses) - 3} more)"
            self.rule_table.setItem(row, 2, QTableWidgetItem(src_text))

            dst_text = ", ".join(rule.dest_addresses[:3])
            if len(rule.dest_addresses) > 3:
                dst_text += f" (+{len(rule.dest_addresses) - 3} more)"
            self.rule_table.setItem(row, 3, QTableWidgetItem(dst_text))

            svc_text = ", ".join(rule.services[:3])
            if len(rule.services) > 3:
                svc_text += f" (+{len(rule.services) - 3} more)"
            self.rule_table.setItem(row, 4, QTableWidgetItem(svc_text))

            action_item = QTableWidgetItem(rule.action.upper())
            if rule.action == "allow":
                action_item.setForeground(QColor("#44BB44"))
            else:
                action_item.setForeground(QColor("#FF4444"))
            action_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.rule_table.setItem(row, 5, action_item)

            log_item = QTableWidgetItem("Yes" if rule.logging_enabled else "No")
            if not rule.logging_enabled:
                log_item.setForeground(QColor("#FF8C00"))
            self.rule_table.setItem(row, 6, log_item)

            rule_findings = [f for f in self.findings if f.rule_id == rule.rule_id]
            worst_severity = "low"
            for f in rule_findings:
                if SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(worst_severity, 99):
                    worst_severity = f.severity
            if rule.disabled:
                worst_severity = "low"

            sev_item = QTableWidgetItem(worst_severity.upper())
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(worst_severity, "#888888")))
            sev_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.rule_table.setItem(row, 7, sev_item)

            self.rule_table.setItem(row, 8, QTableWidgetItem(rule.vendor.upper()))

            for col in range(9):
                item = self.rule_table.item(row, col)
                if item:
                    item.setToolTip(f"Rule {rule.rule_number}: {rule.name or 'Unnamed'}")

        self._apply_filters()

    def _apply_filters(self):
        filter_text = self.rule_filter.text().lower()
        severity = self.severity_filter.currentText().lower()
        vendor_map = {"All": None, "Palo Alto": "paloalto", "Check Point": "checkpoint", "Fortinet": "fortinet"}
        vendor = vendor_map.get(self.vendor_filter.currentText())

        for row in range(self.rule_table.rowCount()):
            show = True
            if filter_text:
                texts = []
                for col in range(self.rule_table.columnCount()):
                    item = self.rule_table.item(row, col)
                    if item:
                        texts.append(item.text().lower())
                if not any(filter_text in t for t in texts):
                    show = False

            if show and severity and severity != "all":
                sev_item = self.rule_table.item(row, 7)
                if sev_item and sev_item.text().lower() != severity:
                    show = False

            if show and vendor:
                vendor_item = self.rule_table.item(row, 8)
                if vendor_item:
                    display_vendor = vendor_item.text().lower()
                    if display_vendor != vendor:
                        show = False

            self.rule_table.setRowHidden(row, not show)

    def _update_findings_table(self):
        self.findings_detail_table.setRowCount(0)
        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        for f in sorted_findings:
            row = self.findings_detail_table.rowCount()
            self.findings_detail_table.insertRow(row)

            num_item = QTableWidgetItem(str(f.rule_number))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.findings_detail_table.setItem(row, 0, num_item)

            self.findings_detail_table.setItem(row, 1, QTableWidgetItem(f.rule_name))

            type_item = QTableWidgetItem(f.finding_type.replace("_", " ").title())
            self.findings_detail_table.setItem(row, 2, type_item)

            sev_item = QTableWidgetItem(f.severity.upper())
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(f.severity, "#888")))
            sev_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.findings_detail_table.setItem(row, 3, sev_item)

            desc_item = QTableWidgetItem(f.description)
            self.findings_detail_table.setItem(row, 4, desc_item)

            evidence_item = QTableWidgetItem(f.evidence)
            self.findings_detail_table.setItem(row, 5, evidence_item)

            remediation_item = QTableWidgetItem(f.remediation)
            self.findings_detail_table.setItem(row, 6, remediation_item)

            refs_item = QTableWidgetItem("\n".join(f.compliance_refs))
            self.findings_detail_table.setItem(row, 7, refs_item)

    def _update_shadow_table(self):
        self.shadow_table.setRowCount(0)
        shadow_findings = [f for f in self.findings if f.finding_type == "shadowed_rule"]
        redundancy_findings = [f for f in self.findings if f.finding_type == "redundant_rule"]
        all_rel = shadow_findings + redundancy_findings

        for f in all_rel:
            row = self.shadow_table.rowCount()
            self.shadow_table.insertRow(row)
            self.shadow_table.setItem(row, 0, QTableWidgetItem(str(f.rule_number)))
            self.shadow_table.setItem(row, 1, QTableWidgetItem(f.rule_name))

            shadowed_by = "N/A"
            for ff in self.findings:
                if ff.finding_type == "shadowed_rule" and ff.rule_id == f.rule_id:
                    for r in self.rules:
                        if r.rule_id != f.rule_id:
                            if r.action == "allow":
                                shadowed_by = f"{r.name} (#{r.rule_number})"
                                break
                    break
            self.shadow_table.setItem(row, 2, QTableWidgetItem(shadowed_by))
            self.shadow_table.setItem(row, 3, QTableWidgetItem(f.evidence.split(".")[0] if f.evidence else ""))
            type_item = QTableWidgetItem(f.finding_type.replace("_", " ").title())
            type_item.setForeground(QColor(SEVERITY_COLORS.get(f.severity, "#888")))
            self.shadow_table.setItem(row, 4, type_item)

    def _update_compliance_heatmap(self):
        self.compliance_heatmap.findings = self.findings
        self.compliance_heatmap.update()

    def _update_report_preview(self):
        if not self.rules:
            self.report_preview.setText("No data loaded. Load a configuration to generate report preview.")
            return
        preview_text = "REPORT PREVIEW\n" + "=" * 60 + "\n\n"
        preview_text += f"Total Rules: {len(self.rules)}\n"
        preview_text += f"Total Findings: {len(self.findings)}\n\n"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        score = max(0, min(100, 100 - (
            counts["critical"] * 10 + counts["high"] * 5 +
            counts["medium"] * 2 + counts["low"] * 1
        )))
        preview_text += f"Compliance Score: {score}%\n\n"

        preview_text += "SEVERITY BREAKDOWN:\n"
        for sev, cnt in counts.items():
            preview_text += f"  {sev.upper()}: {cnt}\n"

        preview_text += "\nFINDINGS (sorted by severity):\n" + "-" * 60 + "\n"
        for f in sorted(self.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))[:10]:
            preview_text += f"[{f.severity.upper()}] Rule #{f.rule_number} ({f.rule_name}): {f.description}\n"

        if len(self.findings) > 10:
            preview_text += f"\n... and {len(self.findings) - 10} more findings\n"

        preview_text += "\n" + "-" * 60 + "\n"
        preview_text += "Export as HTML for full formatted report with styling.\n"
        self.report_preview.setText(preview_text)

    # ----------------------------------------------------------------
    # EXPORT
    # ----------------------------------------------------------------

    def _export_report(self, fmt):
        if not self.findings:
            QMessageBox.warning(self, "No Data", "No findings to export. Load a configuration first.")
            return

        if fmt == "html":
            content = generate_html_report(self.rules, self.findings)
            ext = "html"
            ftype = "HTML Files (*.html)"
        elif fmt == "json":
            content = generate_json_report(self.rules, self.findings)
            ext = "json"
            ftype = "JSON Files (*.json)"
        elif fmt == "csv":
            content = generate_csv_report(self.findings)
            ext = "csv"
            ftype = "CSV Files (*.csv)"
        else:
            return

        default_name = f"firewall_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", default_name, ftype)
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self._log(f"Report exported: {path}")
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            self._log(f"ERROR: Failed to export: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to save report:\n{e}")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = app.palette()
    palette.setColor(palette.ColorRole.Window, QColor("#f5f5f5"))
    palette.setColor(palette.ColorRole.WindowText, QColor("#333333"))
    palette.setColor(palette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(palette.ColorRole.AlternateBase, QColor("#f8f9fa"))
    palette.setColor(palette.ColorRole.Text, QColor("#333333"))
    palette.setColor(palette.ColorRole.Button, QColor("#16213e"))
    palette.setColor(palette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(palette.ColorRole.Highlight, QColor("#1976D2"))
    palette.setColor(palette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    window = FirewallAuditorWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
