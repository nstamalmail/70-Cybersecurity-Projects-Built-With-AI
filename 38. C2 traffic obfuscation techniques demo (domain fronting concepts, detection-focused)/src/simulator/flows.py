"""FlowRecord — the atomic traffic record shared across the whole pipeline.

Every module (generator, pcap writer, detectors, GUI) speaks in FlowRecords.
All domains are reserved-TLD (S5); all IPs are RFC 5737 (S4) — enforced by the
domain/IP pools in ``scenario.py`` and the static safety guard.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Verdict(enum.StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class App(enum.StrEnum):
    DNS = "dns"
    NTP = "ntp"
    HTTP = "http"


@dataclass
class FlowRecord:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str                      # "udp" | "tcp"
    app: str                        # App enum value
    ttl: int = 64
    ip_id: int = 0
    # ---- TLS / HTTP application fields ----
    sni: str = ""                   # TLS Server Name Indication (sensor-visible)
    host: str = ""                  # HTTP Host header / DNS qname (CDN-visible)
    uri: str = "/"
    method: str = "GET"
    status: int = 200
    body: bytes = b""               # synthetic response body (didactic filler)
    ja3: str = ""
    ja3s: str = ""
    encoding_layers: list[str] = field(default_factory=list)
    family: str = "benign"          # benign | campaign | ransomware | dns | ntp | dga_decoy
    note: str = ""                  # human-readable explanation for the GUI
    verdict: str = "clean"          # set by the detection engine

    # ---- convenience ----
    @property
    def tuple_key(self) -> tuple:
        return (self.src, self.sport, self.dst, self.dport, self.proto)

    @property
    def url(self) -> str:
        return f"{self.host or self.sni or '?'}{self.uri}"

    def to_row(self) -> tuple:
        return (
            f"{self.ts:.1f}",
            self.src, self.dst, self.dport, self.proto, self.app,
            self.sni or "-", self.host or "-",
            self.uri if len(self.uri) < 48 else self.uri[:45] + "…",
            self.ja3[:12] if self.ja3 else "-",
            self.family, self.verdict,
        )
