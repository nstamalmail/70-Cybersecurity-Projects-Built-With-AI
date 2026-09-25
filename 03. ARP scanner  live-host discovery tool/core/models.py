"""Data model for the ARP scanner (pure stdlib, no platform imports)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ScanConfig:
    """Single source of truth for one scan run."""

    cidr: str
    timeout: float = 2.0          # informational for SendARP (kept for future engines)
    max_workers: int = 128        # thread-pool width; bounds sweep wall-time
    ports: tuple = ()             # reserved for future use


@dataclass(frozen=True)
class Host:
    """One discovered device."""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""

    def to_row(self) -> tuple[str, str, str, str]:
        """Flat tuple for Treeview / CSV rows."""
        return (self.ip, self.mac, self.vendor, self.hostname)


@dataclass(frozen=True)
class ScanResult:
    """Aggregated outcome of one scan run."""

    cidr: str
    started: datetime
    finished: datetime
    hosts: tuple[Host, ...] = field(default=())

    @property
    def duration_s(self) -> float:
        return (self.finished - self.started).total_seconds()

    def sorted_hosts(self) -> list[Host]:
        """Hosts sorted by numeric IP (not lexicographic)."""
        return sorted(
            self.hosts,
            key=lambda h: int(ipaddress.ip_address(h.ip)),
        )

    def to_json_dict(self) -> dict:
        """Full serialization incl. scan metadata."""
        return {
            "cidr": self.cidr,
            "started": self.started.isoformat(timespec="seconds"),
            "finished": self.finished.isoformat(timespec="seconds"),
            "duration_s": round(self.duration_s, 2),
            "host_count": len(self.hosts),
            "hosts": [
                {
                    "ip": h.ip,
                    "mac": h.mac,
                    "vendor": h.vendor,
                    "hostname": h.hostname,
                }
                for h in self.sorted_hosts()
            ],
        }


@dataclass
class ScanEvent:
    """Message streamed from the scanner thread to the UI."""

    kind: str          # "start" | "progress" | "host" | "done" | "error"
    value: object = None
