"""Optional reverse-DNS name resolver with LRU cache.

Runs in a single worker thread; never blocks the capture thread. Off by
default — enable from Capture → Options in the GUI.
"""

from __future__ import annotations

import socket
import threading
from collections import OrderedDict
from typing import Dict, Optional


class NameResolver:
    def __init__(self, enabled: bool = False, cache_size: int = 4096, timeout: float = 2.0):
        self.enabled = enabled
        self._timeout = timeout
        self._cache: "OrderedDict[str, str]" = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()
        self._queue: "list[str]" = []
        self._pending: set = set()
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._worker is None:
            self._stop.clear()
            self._worker = threading.Thread(target=self._loop, daemon=True, name="dns-resolver")
            self._worker.start()

    def stop(self) -> None:
        self._stop.set()

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        if enabled:
            self.start()

    def lookup(self, ip: str) -> str:
        """Return cached name for ip, or ip itself. Never blocks."""
        if ip.startswith("127.") or ip.endswith(".255"):
            return ip
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
        if self.enabled and ip not in self._pending:
            self._pending.add(ip)
            self._queue.append(ip)
        return ip

    def _loop(self) -> None:
        while not self._stop.is_set():
            if not self._queue:
                self._stop.wait(0.25)
                continue
            ip = self._queue.pop(0)
            try:
                socket.setdefaulttimeout(self._timeout)
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ip
            with self._lock:
                self._cache[ip] = name
                self._cache.move_to_end(ip)
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)
            self._pending.discard(ip)
