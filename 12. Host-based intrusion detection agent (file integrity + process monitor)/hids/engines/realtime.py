"""Real-time FIM monitor built on watchdog.

Windows uses ReadDirectoryChangesW (natively recursive — one watch per root
covers the whole tree). On POSIX, inotify watches are added per directory and
nested directories are scheduled on creation.

Event pipeline (all off the observer's emitter thread):

    watchdog event -> enqueue(path)   [filter: monitored root + exclusions]
                   -> pending dict    [last-event timestamp per path]
                   -> worker loop     [debounce quiet-period, batch coalescing]
                   -> process_fn(path)  (FimEngine._process_path_now:
                                        hash, compare vs baseline, alert)

Debouncing matters: editors/compilers emit many events per save, and hashing a
file mid-write yields unstable digests. A path is processed only after it has
been quiet for ``realtime_debounce_seconds``.

If watchdog is unavailable or no watchable root exists, the monitor degrades
gracefully and the periodic sweep scan remains the detection mechanism.
"""

import logging
import os
import sys
import threading
import time
from typing import Callable, Optional

from ..core.utils import path_excluded

log = logging.getLogger("hids.realtime")

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:  # watchdog optional; periodic sweep still works
    WATCHDOG_AVAILABLE = False
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment]


class _Handler(FileSystemEventHandler):
    """Forwards watchdog events to the monitor, normalizing event types."""

    def __init__(self, monitor: "RealtimeMonitor"):
        self.monitor = monitor

    def on_created(self, event):
        if event.is_directory:
            # POSIX needs an explicit watch for nested dirs; Windows (and any
            # recursively-scheduled observer) would double-report if re-scheduled.
            if sys.platform != "win32":
                self.monitor.watch_new_dir(event.src_path)
            return
        self.monitor.enqueue(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.monitor.enqueue(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return  # children are reported separately; sweep catches stragglers
        self.monitor.enqueue(event.src_path)

    def on_moved(self, event):
        dest = getattr(event, "dest_path", None) or event.src_path
        if not event.is_directory:
            self.monitor.enqueue(dest)


class RealtimeMonitor:
    """Watches monitored paths and feeds debounced paths to ``process_fn``."""

    def __init__(self, config, process_fn: Callable[[str], None]):
        self.config = config
        self.process_fn = process_fn
        self.active = False  # True only when the observer is actually watching
        self._pending: dict = {}
        self._lock = threading.Lock()
        self._wakeup = threading.Event()
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self.observer = None
        self._handler = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        """Start worker (always) and observer (if possible). Returns realtime state."""
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._work_loop, name="realtime-fim", daemon=True)
        self._worker.start()

        if not WATCHDOG_AVAILABLE:
            log.warning("watchdog not installed — real-time FIM disabled; "
                        "falling back to interval scans (pip install watchdog)")
            return False

        roots = self._monitored_roots()
        if not roots:
            log.info("No watchable monitored paths — real-time FIM idle")
            return False
        try:
            self.observer = Observer(timeout=1.0)
            self._handler = _Handler(self)
            scheduled = 0
            for root, is_file in roots:
                if is_file:
                    parent = os.path.dirname(os.path.abspath(root)) or "."
                    self.observer.schedule(self._handler, parent, recursive=False)
                    scheduled += 1
                elif os.path.isdir(root):
                    self.observer.schedule(self._handler, root, recursive=True)
                    scheduled += 1
            if scheduled == 0:
                self.observer = None
                return False
            self.observer.start()
            self.active = True
            log.info("Real-time FIM active: watching %d root(s)", scheduled)
            return True
        except Exception:
            log.exception("Failed to start watchdog observer — "
                          "falling back to interval scans")
            self.observer = None
            self.active = False
            return False

    def stop(self) -> None:
        self._stop_event.set()
        self._wakeup.set()
        if self.observer is not None:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                log.debug("Observer stop raised", exc_info=True)
            self.observer = None
            self.active = False
        if self._worker is not None:
            self._worker.join(timeout=2)
            self._worker = None

    def watch_new_dir(self, path: str) -> None:
        """POSIX-only: add a recursive watch for a newly created directory."""
        if self.observer is not None and self._handler is not None:
            try:
                self.observer.schedule(self._handler, path, recursive=True)
            except Exception:
                log.debug("Nested watch failed for %s", path, exc_info=True)

    # -- event intake --------------------------------------------------------
    def enqueue(self, path: str) -> None:
        """Record a change event for a path (called from observer threads)."""
        norm = self._normalize(path)
        if not self._path_relevant(norm):
            return
        with self._lock:
            self._pending[norm] = time.time()
        self._wakeup.set()

    def _normalize(self, path: str) -> str:
        try:
            return os.path.normpath(os.path.abspath(path))
        except Exception:
            return path

    def _monitored_roots(self):
        out = []
        for root in (self.config.get("monitored_paths") or []):
            if not root:
                continue
            out.append((root, os.path.isfile(root)))
        return out

    def _path_relevant(self, path: str) -> bool:
        cfg_paths = self.config.get("monitored_paths") or []
        if not cfg_paths:
            return False
        if path_excluded(path, self.config.get("exclude_patterns") or []):
            return False
        norm = os.path.normcase(path)
        for root in cfg_paths:
            rnorm = os.path.normcase(self._normalize(root))
            if norm == rnorm:
                return True
            if norm.startswith(rnorm + os.sep) or norm.startswith(rnorm + "/"):
                return True
        return False

    # -- worker --------------------------------------------------------------
    def _work_loop(self) -> None:
        debounce = max(0.1, float(self.config.get("realtime_debounce_seconds", 1.0)))
        while not self._stop_event.is_set():
            now = time.time()
            due = []
            with self._lock:
                for path, last_event in list(self._pending.items()):
                    if now - last_event >= debounce:
                        due.append(path)
                        del self._pending[path]
            for path in due:
                if self._stop_event.is_set():
                    break
                try:
                    self.process_fn(path)
                except Exception:
                    log.exception("Real-time processing failed for %s", path)
            self._wakeup.wait(0.2)
            self._wakeup.clear()
