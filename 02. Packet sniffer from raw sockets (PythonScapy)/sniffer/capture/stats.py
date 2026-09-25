"""Statistics aggregator for live capture sessions."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import Packet


@dataclass
class StatisticsSnapshot:
    total: int = 0
    matched: int = 0
    dropped: int = 0
    bytes_total: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    elapsed: float = 0.0
    bps: float = 0.0

    @property
    def pps(self) -> float:
        return self.total / self.elapsed if self.elapsed > 0 else 0.0


class StatisticsAggregator:
    """Thread-safe counters updated by the GUI drain path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time: Optional[float] = None
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._total = 0
            self._matched = 0
            self._dropped = 0
            self._bytes = 0
            self._protocols: Dict[str, int] = {}
            self._hosts: Dict[str, int] = {}
            self._start_time = time.time()

    def start_session(self) -> None:
        self.reset()

    def update(self, pkt: Packet, matched: bool, dropped: int = 0) -> None:
        with self._lock:
            self._total += 1
            self._bytes += pkt.frame_len
            if matched:
                self._matched += 1
            if dropped:
                self._dropped = dropped
            self._protocols[pkt.protocol] = self._protocols.get(pkt.protocol, 0) + 1
            for a in (pkt.src, pkt.dst):
                if a and a != "?":
                    self._hosts[a] = self._hosts.get(a, 0) + 1

    def snapshot(self) -> StatisticsSnapshot:
        with self._lock:
            elapsed = max(time.time() - (self._start_time or time.time()), 0.001)
            return StatisticsSnapshot(
                total=self._total,
                matched=self._matched,
                dropped=self._dropped,
                bytes_total=self._bytes,
                protocol_counts=dict(self._protocols),
                top_talkers=sorted(self._hosts.items(), key=lambda kv: kv[1], reverse=True)[:15],
                elapsed=elapsed,
                bps=self._bytes / elapsed,
            )
