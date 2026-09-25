"""Wordlist PSK verification for WNA (own lab handshakes only).

The built-in cracker verifies candidate passphrases directly against the
captured M1/M2 MIC (architecture.md §3.3 Crack Engine, 'internal-py' backend).
External backends (aircrack-ng / hashcat mode 22000) are detected at runtime
and offered as faster handoff options with the exact command line.
"""

from __future__ import annotations

import os
import queue
import shutil
import threading
from dataclasses import dataclass, field
from typing import List, Optional

from app.core.models import VerificationResult
from app.core.pcap import EapolFrame
from app.core.verifier import verify_psk


def has_external_tools() -> dict:
    return {
        "aircrack-ng": shutil.which("aircrack-ng") is not None,
        "hashcat": shutil.which("hashcat") is not None,
    }


@dataclass
class CrackConfig:
    wordlist_path: str = ""
    essid: str = ""
    workers: int = 4
    max_candidates: int = 2_000_000


@dataclass
class CrackState:
    tested: int = 0
    total: int = 0
    found: str = ""
    running: bool = False
    error: str = ""
    duration: float = 0.0
    progress_events: "queue.Queue | None" = None


class WordlistCracker(threading.Thread):
    """Multi-threaded PBKDF2 PSK verification against one M1/M2 pair."""

    def __init__(self, result: VerificationResult, cfg: CrackConfig,
                 events: "queue.Queue"):
        super().__init__(daemon=True)
        self.vr = result
        self.cfg = cfg
        self.events = events
        self.state = CrackState(progress_events=events)
        self._cancel = threading.Event()
        self._m1: Optional[EapolFrame] = None
        self._m2: Optional[EapolFrame] = None

    def stop(self) -> None:
        self._cancel.set()

    def _log(self, msg: str) -> None:
        self.events.put({"type": "log", "message": msg})

    def _prepare_pair(self) -> bool:
        from app.core.pcap import extract_eapol_frames
        eapols, _aps, _total = extract_eapol_frames(self.vr.capture_path)
        key_frames = [f for f in eapols if f.is_key_frame]
        m1 = next((f for f in key_frames if f.message == "M1"), None)
        m2 = next((f for f in key_frames if f.message == "M2"), None)
        if not (m1 and m2):
            self.state.error = "capture lacks a usable M1/M2 pair"
            return False
        self._m1, self._m2 = m1, m2
        return True

    def _worker(self, paths_iter_lock, paths_iter, results: List[str]):
        while not self._cancel.is_set() and not results:
            with paths_iter_lock:
                try:
                    line = next(paths_iter)
                except StopIteration:
                    return
            psk = line.rstrip("\r\n")
            if not psk or len(psk) < 8:
                continue
            self.state.tested += 1
            if verify_psk(psk, self.cfg.essid, self._m1.src, self._m1.dst,
                          self._m1, self._m2):
                results.append(psk)
                return

    def run(self) -> None:
        import time
        t0 = time.time()
        self.state.running = True
        try:
            if not self._prepare_pair():
                self._log(f"✖ {self.state.error}")
                return
            self._log(f"cracking: essid={self.cfg.essid!r} "
                      f"ap={self._m1.src} sta={self._m1.dst}")
            if not os.path.exists(self.cfg.wordlist_path):
                self.state.error = f"wordlist not found: {self.cfg.wordlist_path}"
                self._log(f"✖ {self.state.error}")
                return

            results: List[str] = []
            with open(self.cfg.wordlist_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                lines = iter(fh)
                threads = []
                lock = threading.Lock()
                for _ in range(max(1, self.cfg.workers)):
                    t = threading.Thread(target=self._worker,
                                         args=(lock, lines, results),
                                         daemon=True)
                    t.start()
                    threads.append(t)
                while any(t.is_alive() for t in threads):
                    if self._cancel.is_set():
                        break
                    self.events.put({"type": "crack_progress",
                                     "tested": self.state.tested,
                                     "found": results[0] if results else ""})
                    time.sleep(0.5)
                for t in threads:
                    t.join(timeout=2)

            if results:
                self.state.found = results[0]
                self._log(f"🚩 PSK FOUND: {self.state.found!r}")
                self.events.put({"type": "crack_done", "found": self.state.found})
            elif self._cancel.is_set():
                self._log("cracking cancelled")
            else:
                self._log("wordlist exhausted — PSK not found")
                self.events.put({"type": "crack_done", "found": ""})
        except Exception as exc:  # noqa: BLE001
            self.state.error = f"{exc.__class__.__name__}: {exc}"
            self._log(f"✖ crack error: {self.state.error}")
        finally:
            self.state.duration = time.time() - t0
            self.state.running = False
