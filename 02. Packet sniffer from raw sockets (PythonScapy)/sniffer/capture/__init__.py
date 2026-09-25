"""Capture subpackage: engines, controller, pcap I/O, platform backends."""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .engine import (
    CaptureEngine,
    PcapFileEngine,
    RawSocketEngine,
    SnifferConfig,
    list_interfaces,
)
from .pcap_file import PcapWriter, PcapReader

__all__ = [
    "CaptureEngine", "RawSocketEngine", "PcapFileEngine", "SnifferConfig",
    "CaptureController", "PcapWriter", "PcapReader", "list_interfaces",
]


class CaptureController:
    """Session state machine coordinating engine, statistics and pcap sink.

    States: idle → capturing ⇄ paused → idle
    The controller owns the engine thread and routes packets to:
      * a per-packet callback (GUI queue path), and
      * an optional PcapWriter sink (recording toggle).
    """

    def __init__(self) -> None:
        self.engine: Optional[CaptureEngine] = None
        self.writer: Optional[PcapWriter] = None
        self.state = "idle"
        self._on_packet: Optional[Callable] = None
        self._on_state: Optional[Callable[[str], None]] = None
        self._drain_thread: Optional[threading.Thread] = None
        self._stats_cb: Optional[Callable] = None
        self._record = False

    # -- wiring ----------------------------------------------------------------
    def set_on_packet(self, cb: Callable) -> None:
        self._on_packet = cb

    def set_on_state(self, cb: Callable[[str], None]) -> None:
        self._on_state = cb

    def set_stats_callback(self, cb: Callable) -> None:
        self._stats_cb = cb

    # -- recording ----------------------------------------------------------------
    def start_recording(self, path: str) -> None:
        self.writer = PcapWriter(path)

    def stop_recording(self) -> None:
        if self.writer:
            self.writer.close()
            self.writer = None

    @property
    def recording(self) -> bool:
        return self.writer is not None

    # -- session ----------------------------------------------------------------
    def start(self, config: SnifferConfig, engine: Optional[CaptureEngine] = None) -> None:
        if self.state != "idle":
            raise RuntimeError("capture already active")
        self.engine = engine or RawSocketEngine(config)
        self.engine.on_error(self._handle_error)
        self._on_packet = self._on_packet or (lambda pkt: None)
        self.state = "capturing"
        if self._on_state:
            self._on_state(self.state)
        self.engine.start()
        self._drain_thread = threading.Thread(
            target=self._drain_loop, name="drain", daemon=True)
        self._drain_thread.start()

    def _drain_loop(self) -> None:
        """Pull packets from the engine queue → per-packet callback + sink."""
        eng = self.engine
        while eng and not eng.stop_event.is_set() or eng.queue.qsize():
            try:
                pkt = eng.queue.get(timeout=0.2)
            except Exception:
                continue
            if self._on_packet:
                try:
                    self._on_packet(pkt)
                except Exception:
                    pass
            if self.writer:
                try:
                    self.writer.write_packet(pkt.timestamp, pkt.raw, pkt.orig_len)
                except Exception:
                    pass
        # engine thread finished → state transition
        if self.state == "capturing":
            self.state = "idle"
            if self._on_state:
                self._on_state("idle")

    def stop(self) -> None:
        if self.engine:
            self.engine.stop()
        self.state = "idle"
        if self._on_state:
            self._on_state("idle")
        self._join_drain()
        self.stop_recording()

    def pause(self) -> None:
        if self.engine:
            self.engine.pause()
            self.state = "paused"
            if self._on_state:
                self._on_state("paused")

    def resume(self) -> None:
        if self.engine:
            self.engine.resume()
            self.state = "capturing"
            if self._on_state:
                self._on_state("capturing")

    def _join_drain(self, timeout: float = 2.0) -> None:
        t = self._drain_thread
        if t and t.is_alive():
            t.join(timeout=timeout)
            self._drain_thread = None

    def _handle_error(self, msg: str) -> None:
        self.state = "error"
        if self._on_state:
            self._on_state(self.state)

    def last_error(self) -> str:
        eng = self.engine
        return getattr(eng, "_last_error", "") if eng else ""

    # -- counters passthrough ------------------------------------------------------
    @property
    def dropped(self) -> int:
        return self.engine.dropped if self.engine else 0

    @property
    def captured(self) -> int:
        return self.engine.captured if self.engine else 0
