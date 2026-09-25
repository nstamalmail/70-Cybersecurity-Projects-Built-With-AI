"""Core domain objects: Packet, ProtocolLayer, statistics models.

Value objects are immutable (frozen dataclasses) per the architecture's
immutability principle. Dissectors append ProtocolLayer objects to a Packet.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class TruncatedPacketError(Exception):
    """Raised by dissectors when a buffer is too short to contain a header."""


# Well-known IP protocol numbers
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

# Protocol display classes -> tag colors used by the GUI
PROTOCOL_COLORS = {
    "TCP": "#dbe9f6",
    "UDP": "#d8ecd4",
    "DNS": "#f5edc0",
    "HTTP": "#fbdcc0",
    "TLS": "#e5dbf2",
    "ARP": "#f3d3e3",
    "ICMP": "#d0e8e8",
    "IPv6": "#e8e8e8",
    "MALFORMED": "#f6c6c6",
}


def classify_protocol(top_proto: str) -> str:
    """Map top-layer protocol name to a GUI color class."""
    if top_proto in PROTOCOL_COLORS:
        return top_proto
    if top_proto.startswith("ICMP"):
        return "ICMP"
    if top_proto.startswith("HTTP"):
        return "HTTP"
    if top_proto.startswith("TLS"):
        return "TLS"
    if top_proto.startswith("QUIC"):
        return "UDP"
    if top_proto.startswith(("TCP", "UDP", "IPv")):
        return top_proto[:3]
    return "OTHER"


@dataclass(frozen=True)
class ProtocolLayer:
    """One decoded protocol layer within a packet.

    ``fields`` maps human-readable field names to display values.
    ``offset``/``length`` locate the layer header inside the raw frame so the
    hex view can highlight the selected layer's bytes.
    """

    name: str
    fields: Dict[str, Any]
    offset: int
    length: int

    def summary(self) -> str:
        parts = []
        for key in ("src", "dst", "sport", "dport", "type", "opcode"):
            if key in self.fields:
                parts.append(f"{key}={self.fields[key]}")
        return f"{self.name}: " + ", ".join(parts) if parts else self.name


@dataclass(frozen=True)
class Packet:
    """A captured packet: raw bytes plus timestamp and dissection results."""

    number: int                      # 1-based capture sequence number
    timestamp: float                 # epoch seconds with sub-second precision
    raw: bytes                       # full frame as captured (may be truncated)
    orig_len: int                    # original wire length (if snaplen truncated)
    layers: Tuple[ProtocolLayer, ...] = ()
    malformed: bool = False

    # ---- convenience accessors -------------------------------------------
    @property
    def frame_len(self) -> int:
        return len(self.raw)

    def layer(self, name: str) -> Optional[ProtocolLayer]:
        name = name.upper()
        for l in self.layers:
            if l.name.upper() == name:
                return l
        return None

    def field(self, layer: str, key: str) -> Any:
        lay = self.layer(layer)
        return lay.fields.get(key) if lay else None

    @property
    def top_layer(self) -> Optional[ProtocolLayer]:
        return self.layers[-1] if self.layers else None

    @property
    def protocol(self) -> str:
        top = self.top_layer
        return top.name if top else "Unknown"

    # ---- endpoints --------------------------------------------------------
    @staticmethod
    def _fmt_addr(value: Any) -> str:
        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(value)
        return str(value)

    @property
    def src(self) -> str:
        for lname in ("TCP", "UDP", "ICMP", "ICMPv6", "IPv4", "IPv6", "ARP"):
            lay = self.layer(lname)
            if lay and "src" in lay.fields:
                return self._fmt_addr(lay.fields["src"])
        return "?"

    @property
    def dst(self) -> str:
        for lname in ("TCP", "UDP", "ICMP", "ICMPv6", "IPv4", "IPv6", "ARP"):
            lay = self.layer(lname)
            if lay and "dst" in lay.fields:
                return self._fmt_addr(lay.fields["dst"])
        return "?"

    @property
    def src_port(self) -> Optional[int]:
        for lname in ("TCP", "UDP"):
            lay = self.layer(lname)
            if lay and "sport" in lay.fields:
                return int(lay.fields["sport"])
        return None

    @property
    def dst_port(self) -> Optional[int]:
        for lname in ("TCP", "UDP"):
            lay = self.layer(lname)
            if lay and "dport" in lay.fields:
                return int(lay.fields["dport"])
        return None

    # ---- display ----------------------------------------------------------
    @property
    def time_str(self) -> str:
        secs = int(self.timestamp)
        frac = self.timestamp - secs
        return f"{secs % 86400:02d}:{int(frac * 1000000):06d}"

    @property
    def info(self) -> str:
        """Short one-line summary shown in the packet list."""
        top = self.top_layer
        if self.malformed or top is None:
            return "Malformed packet"
        n = top.name
        f = top.fields
        try:
            if n == "TCP":
                flags = [k for k in f if k.startswith("flags.") and f[k]]
                fl = ",".join(k.split(".", 1)[1].upper() for k in flags)
                info = f"{f.get('sport')} → {f.get('dport')}"
                info += f" [{fl}]" if fl else ""
                info += f" Seq={f.get('seq')}" if "seq" in f else ""
                info += f" Win={f.get('win')}" if "win" in f else ""
                info += f" Len={f.get('payload_len')}" if "payload_len" in f else ""
                return info
            if n == "UDP":
                return f"{f.get('sport')} → {f.get('dport')} Len={f.get('payload_len', '')}"
            if n == "DNS":
                q = f.get("question", "")
                return f"{f.get('qr', '')}{(' ' + q) if q else ''}".strip() or "DNS"
            if n.startswith("HTTP"):
                return f.get("line", n)
            if n.startswith("TLS"):
                return f.get("line", n)
            if n == "ARP":
                op = {1: "request", 2: "reply"}.get(f.get("opcode", 0), str(f.get("opcode")))
                return f"{op}: {f.get('spa')} → {f.get('tpa')}"
            if n.startswith("ICMP"):
                return f"type={f.get('type')} code={f.get('code')}"
            if n == "IPv4":
                return f"{f.get('src')} → {f.get('dst')} proto={f.get('proto_name')}"
            if n == "IPv6":
                return f"{f.get('src')} → {f.get('dst')} nh={f.get('proto_name')}"
            if n == "Ethernet":
                return f"{f.get('src')} → {f.get('dst')} type=0x{f.get('ethertype', 0):04x}"
        except Exception:
            pass
        return n

    def color_class(self) -> str:
        return "MALFORMED" if self.malformed else classify_protocol(self.protocol)

    def summary_row(self) -> Tuple[str, str, str, str, str, str, str]:
        """Seven columns for the packet list Treeview."""
        return (
            str(self.number),
            self.time_str,
            self.src,
            self.dst,
            self.protocol,
            str(self.frame_len),
            self.info,
        )


# ---------------------------------------------------------------------------
# Live statistics
# ---------------------------------------------------------------------------

@dataclass
class StatisticsSnapshot:
    """Immutable snapshot handed from the capture thread to the GUI."""

    total: int = 0
    matched: int = 0
    dropped_queue: int = 0
    bytes_total: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    elapsed: float = 0.0
    bps: float = 0.0

    @property
    def pps(self) -> float:
        return self.total / self.elapsed if self.elapsed > 0 else 0.0


class StatisticsAggregator:
    """Thread-safe counters updated by the capture thread; snapshotted for GUI."""

    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self._total = 0
        self._matched = 0
        self._dropped = 0
        self._bytes = 0
        self._protocols: Dict[str, int] = {}
        self._hosts: Dict[str, int] = {}

    def reset(self) -> None:
        with self._lock:
            self._total = self._matched = self._dropped = 0
            self._bytes = 0
            self._protocols.clear()
            self._hosts.clear()

    def update(self, pkt: Packet, matched: bool) -> None:
        with self._lock:
            self._total += 1
            self._bytes += pkt.frame_len
            if matched:
                self._matched += 1
            self._protocols[pkt.protocol] = self._protocols.get(pkt.protocol, 0) + 1
            for a in (pkt.src, pkt.dst):
                if a != "?":
                    self._hosts[a] = self._hosts.get(a, 0) + 1

    def add_dropped(self, n: int = 1) -> None:
        with self._lock:
            self._dropped += n

    def snapshot(self, elapsed: float) -> StatisticsSnapshot:
        with self._lock:
            return StatisticsSnapshot(
                total=self._total,
                matched=self._matched,
                dropped_queue=self._dropped,
                bytes_total=self._bytes,
                protocol_counts=dict(self._protocols),
                top_talkers=sorted(self._hosts.items(), key=lambda kv: kv[1], reverse=True)[:15],
                elapsed=elapsed,
                bps=(self._bytes / elapsed) if elapsed > 0 else 0.0,
            )
