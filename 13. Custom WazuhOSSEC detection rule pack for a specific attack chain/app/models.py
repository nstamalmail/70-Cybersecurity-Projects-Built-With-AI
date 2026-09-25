"""Core domain model for the Wazuh/OSSEC rule pack builder.

Single source of truth for everything the GUI edits. Pure dataclasses,
no UI or XML logic — that lives in generators.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ConditionType(str, Enum):
    MATCH = "match"
    REGEX = "regex"
    FIELD = "field"
    FREQUENCY = "frequency"


# ATT&CK tactic catalog used for dropdowns and validation.
MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Decoders that ship with Wazuh/OSSEC — a rule may reference any of these
# without defining a custom decoder.
BUILTIN_DECODERS = [
    "syslog",
    "json",
    "windows",
    "eventchannel",
    "web-accesslog",
    "apache-accesslog",
    "nginx",
    "iis",
    "firewall",
    "ssh",
    "smtp",
    "pam",
    "auditd",
    "named",
    "docker",
    "mysql",
    "postgresql",
    "microsoft",
    "o365",
    "aws",
]

MITRE_ID_RE = re.compile(r"^T\d{3,4}(\.\d{3})?$")


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    rule_id: int = 100000
    level: int = 7
    groups: list[str] = field(default_factory=lambda: ["attack_chain"])
    description: str = ""
    decoder: str = "syslog"
    condition: ConditionType = ConditionType.MATCH
    pattern: str = ""
    field_name: str = ""
    frequency: int = 0
    timeframe: int = 0
    mitre_id: str = ""
    mitre_tactic: str = ""

    # -- helpers ------------------------------------------------------------
    def groups_str(self) -> str:
        return ",".join(self.groups)

    def set_groups(self, value: str) -> None:
        self.groups = [g.strip() for g in value.split(",") if g.strip()]

    def has_mitre(self) -> bool:
        return bool(self.mitre_id or self.mitre_tactic)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["condition"] = self.condition.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DetectionRule":
        d = dict(d)
        d["condition"] = ConditionType(d.get("condition", "match"))
        return cls(**d)


@dataclass
class AttackTechnique:
    technique_id: str = ""          # e.g. T1059.003
    name: str = ""
    description: str = ""
    tactic: str = ""                # ATT&CK tactic
    rules: list[DetectionRule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic,
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackTechnique":
        return cls(
            technique_id=d.get("technique_id", ""),
            name=d.get("name", ""),
            description=d.get("description", ""),
            tactic=d.get("tactic", ""),
            rules=[DetectionRule.from_dict(r) for r in d.get("rules", [])],
        )


@dataclass
class AttackStep:
    name: str = ""
    description: str = ""
    techniques: list[AttackTechnique] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "techniques": [t.to_dict() for t in self.techniques],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackStep":
        return cls(
            name=d.get("name", ""),
            description=d.get("description", ""),
            techniques=[AttackTechnique.from_dict(t) for t in d.get("techniques", [])],
        )


@dataclass
class AttackChain:
    name: str = "Untitled Attack Chain"
    description: str = ""
    steps: list[AttackStep] = field(default_factory=list)

    # -- convenience accessors ----------------------------------------------
    def all_techniques(self) -> list[AttackTechnique]:
        return [t for step in self.steps for t in step.techniques]

    def all_rules(self) -> list[DetectionRule]:
        return [r for t in self.all_techniques() for r in t.rules]

    def rule_ids(self) -> set[int]:
        return {r.rule_id for r in self.all_rules()}

    def count_rules(self) -> int:
        return sum(len(t.rules) for t in self.all_techniques())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackChain":
        return cls(
            name=d.get("name", "Untitled Attack Chain"),
            description=d.get("description", ""),
            steps=[AttackStep.from_dict(s) for s in d.get("steps", [])],
        )


@dataclass
class CustomDecoder:
    name: str = ""
    prematch: str = ""
    regex: str = ""
    order: str = ""
    parent: str = "syslog"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CustomDecoder":
        return cls(**d)


@dataclass
class PackOptions:
    base_rule_id: int = 100000
    group_name: str = "attack_chain"
    rule_filename: str = "local_rules.xml"
    decoder_filename: str = "local_decoders.xml"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PackOptions":
        return cls(**d)


# ---------------------------------------------------------------------------
# Full project = chain + decoders + options (what save/load serializes)
# ---------------------------------------------------------------------------

PROJECT_FORMAT_VERSION = 1


@dataclass
class RulePackProject:
    version: int = PROJECT_FORMAT_VERSION
    chain: AttackChain = field(default_factory=AttackChain)
    decoders: list[CustomDecoder] = field(default_factory=list)
    options: PackOptions = field(default_factory=PackOptions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "wazuh_rule_pack_builder",
            "version": self.version,
            "chain": self.chain.to_dict(),
            "decoders": [d.to_dict() for d in self.decoders],
            "options": self.options.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RulePackProject":
        return cls(
            version=d.get("version", PROJECT_FORMAT_VERSION),
            chain=AttackChain.from_dict(d.get("chain", {})),
            decoders=[CustomDecoder.from_dict(x) for x in d.get("decoders", [])],
            options=PackOptions.from_dict(d.get("options", {})),
        )