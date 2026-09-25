"""Core domain models for WNA (architecture.md §3.4)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ENCRYPTION_TYPES = ["WPA2-PSK", "WPA3-SAE", "WPA2-Enterprise", "WPA-PSK",
                    "WEP", "Open"]
COMPLETENESS = ["complete", "partial", "none"]
CRACK_TOOLS = ["aircrack-ng", "hashcat", "internal-py"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class VerificationResult:
    """Outcome of EAPOL/PMKID analysis of one capture file."""

    capture_path: str
    bssid: str = ""
    essid: str = ""
    encryption: str = "WPA2-PSK"
    handshake_captured: bool = False
    handshake_completeness: str = "none"     # complete / partial / none
    messages_present: List[str] = field(default_factory=list)   # ['M1','M2',...]
    pmkid_captured: bool = False
    aps_seen: List[Dict[str, Any]] = field(default_factory=list)
    stations_seen: List[str] = field(default_factory=list)
    eapol_frames: int = 0
    total_packets: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture_path": self.capture_path, "bssid": self.bssid,
            "essid": self.essid, "encryption": self.encryption,
            "handshake_captured": self.handshake_captured,
            "handshake_completeness": self.handshake_completeness,
            "messages_present": self.messages_present,
            "pmkid_captured": self.pmkid_captured,
            "aps_seen": self.aps_seen, "stations_seen": self.stations_seen,
            "eapol_frames": self.eapol_frames,
            "total_packets": self.total_packets, "notes": self.notes,
        }

    def summary(self) -> str:
        if self.handshake_captured:
            return (f"complete 4-way handshake ({', '.join(self.messages_present)}) "
                    f"for {self.essid or self.bssid}")
        if self.pmkid_captured:
            return f"PMKID captured for {self.essid or self.bssid}"
        if self.messages_present:
            return (f"partial EAPOL only ({', '.join(self.messages_present)}) "
                    f"for {self.essid or self.bssid}")
        return "no handshake material found"


@dataclass
class AuditTarget:
    """One allowlisted lab AP and its audit outcome."""

    bssid: str
    essid: str = ""
    channel: int = 0
    encryption: str = "WPA2-PSK"
    handshake_captured: bool = False
    handshake_completeness: str = "none"
    messages_present: List[str] = field(default_factory=list)
    pmkid_captured: bool = False
    hash_file: str = ""
    crack_attempted: bool = False
    crack_tool: str = ""
    crack_result: str = ""            # password if cracked, else ''
    crack_duration_seconds: float = 0.0
    evidence_hashes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid, "essid": self.essid, "channel": self.channel,
            "encryption": self.encryption,
            "handshake_captured": self.handshake_captured,
            "handshake_completeness": self.handshake_completeness,
            "messages_present": self.messages_present,
            "pmkid_captured": self.pmkid_captured,
            "hash_file": self.hash_file,
            "crack_attempted": self.crack_attempted,
            "crack_tool": self.crack_tool,
            "crack_result": self.crack_result,
            "crack_duration_seconds": self.crack_duration_seconds,
            "evidence_hashes": self.evidence_hashes,
        }


@dataclass
class WirelessAudit:
    """One audit session (scope allowlist + targets + outcomes)."""

    audit_id: str = ""
    adapter: str = ""
    monitor_interface: str = ""
    allowlist: List[str] = field(default_factory=list)   # BSSIDs
    targets: List[AuditTarget] = field(default_factory=list)
    capture_method: str = "verification-only"   # classic / pmkid / hybrid
    timestamp: float = field(default_factory=time.time)
    notes: str = ""
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "audit_id": self.audit_id,
            "adapter": self.adapter,
            "monitor_interface": self.monitor_interface,
            "allowlist": self.allowlist,
            "targets": [t.to_dict() for t in self.targets],
            "capture_method": self.capture_method,
            "timestamp": self.timestamp, "notes": self.notes,
        }


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)
