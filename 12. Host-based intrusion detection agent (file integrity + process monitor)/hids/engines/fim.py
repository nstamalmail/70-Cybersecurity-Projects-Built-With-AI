"""FIM engine: cryptographic baseline + verification + burst detection.

Runs as a daemon thread; communicates with the GUI exclusively via EventBus.
All methods are also callable synchronously for tests and manual scans.
"""

import logging
import os
import threading
import time
from collections import deque
from typing import Callable, List, Optional

from ..core import events as ev
from ..core.models import Alert, ChangeRecord, FileRecord
from ..core.utils import now, path_excluded, sha256_file, ts_str
from .realtime import RealtimeMonitor

log = logging.getLogger("hids.fim")

SEV_BY_CHANGE = {"ADDED": "LOW", "MODIFIED": "MEDIUM", "DELETED": "MEDIUM"}
DEDUP_WINDOW = 30.0  # seconds; sweep + realtime can race on the same file


class FimEngine(threading.Thread):
    def __init__(self, config, db, bus):
        super().__init__(name="fim-engine", daemon=True)
        self.config = config
        self.db = db
        self.bus = bus
        self.stop_event = threading.Event()
        self.scan_count = 0
        self._recent: deque = deque()  # (timestamp, change_count)
        self._last_burst = 0.0
        self.realtime: Optional[RealtimeMonitor] = None
        self.realtime_active = False
        self._recent_alerts: dict = {}  # (path, change) -> ts  [dedup]

    # -- lifecycle --------------------------------------------------------
    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        log.info("FIM engine started (interval=%ss)", self.config.get("scan_interval_seconds"))
        self._start_realtime()
        self.bus.post(ev.STATUS, {"engine": "fim", "running": True})
        while not self.stop_event.is_set():
            try:
                if self.db.baseline_count() > 0:
                    self.verify()  # periodic sweep — safety net for realtime
                else:
                    log.info("No baseline yet — build one in the File Integrity tab")
            except Exception:
                log.exception("FIM sweep failed")
            self.stop_event.wait(max(10, int(self.config.get("scan_interval_seconds", 300))))
        self._stop_realtime()
        self.bus.post(ev.STATUS, {"engine": "fim", "running": False})
        log.info("FIM engine stopped")

    def _start_realtime(self) -> None:
        if not self.config.get("realtime_fim", True):
            log.info("Real-time FIM disabled in settings — interval scans only")
            return
        try:
            self.realtime = RealtimeMonitor(self.config, self._process_path_now)
            self.realtime_active = self.realtime.start()
        except Exception:
            log.exception("Real-time FIM failed to start — interval scans only")
            self.realtime = None
            self.realtime_active = False
        self.bus.post(ev.STATUS, {"engine": "fim_realtime", "running": self.realtime_active})

    def _stop_realtime(self) -> None:
        if self.realtime is not None:
            self.realtime.stop()
            self.realtime = None
        self.realtime_active = False

    # -- discovery --------------------------------------------------------
    def _exclude(self):
        return self.config.get("exclude_patterns") or []

    @staticmethod
    def _norm(path: str) -> str:
        """Normalize separators/case basis so realtime events and sweep results
        address baseline rows identically."""
        try:
            return os.path.normpath(os.path.abspath(path))
        except Exception:
            return path

    def _iter_files(self, roots) -> int:
        """Yield file paths under roots, applying exclusions (dirs pruned)."""
        excl = self._exclude()
        for root in roots:
            if not root:
                continue
            if path_excluded(root, excl):
                continue
            if os.path.isfile(root):
                yield self._norm(root)
                continue
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not path_excluded(os.path.join(dirpath, d), excl)
                ]
                for fname in filenames:
                    full = self._norm(os.path.join(dirpath, fname))
                    if not path_excluded(full, excl):
                        yield full

    def _count_files(self, roots) -> int:
        return sum(1 for _ in self._iter_files(roots))

    # -- baseline ---------------------------------------------------------
    def build_baseline(self, progress: Optional[Callable] = None) -> dict:
        roots = list(self.config.get("monitored_paths") or [])
        if not roots:
            log.warning("No monitored paths configured")
            return {"files": 0, "errors": 0}
        max_size = int(self.config.get("max_file_size_mb", 100)) * 1024 * 1024
        records: List[FileRecord] = []
        errors = 0
        started = now()
        total = self._count_files(roots)
        for i, path in enumerate(self._iter_files(roots), 1):
            if progress and (i % 25 == 0 or i == total):
                self.bus.post(ev.SCAN_PROGRESS, {"done": i, "total": total, "phase": "baseline"})
                progress(i, total, path)
            try:
                st = os.stat(path)
            except OSError:
                errors += 1
                continue
            digest = sha256_file(path, max_bytes=max_size)
            if digest is None:
                errors += 1
                continue
            records.append(FileRecord(path, st.st_size, st.st_mtime, digest))
        self.db.replace_baseline(records)
        self.db.set_meta("baseline_built", str(started))
        self.db.set_meta("baseline_count", str(len(records)))
        self.db.set_meta("baseline_fingerprint", self.db.baseline_fingerprint())
        log.info("Baseline built: %d files (%d errors) in %.1fs",
                 len(records), errors, now() - started)
        return {"files": len(records), "errors": errors}

    # -- verification -----------------------------------------------------
    def verify(self, full: bool = False) -> List[ChangeRecord]:
        """Compare disk with baseline; apply changes to DB; emit alerts/events."""
        roots = list(self.config.get("monitored_paths") or [])
        if not roots or self.db.baseline_count() == 0:
            return []
        scan_id = self.db.start_scan()
        started = now()
        excl = self._exclude()
        max_size = int(self.config.get("max_file_size_mb", 100)) * 1024 * 1024
        baseline = {r["path"]: r for r in self.db.all_baseline()}

        changes: List[ChangeRecord] = []
        seen: set = set()
        scanned = errors = 0

        for path in self._iter_files(roots):
            if path_excluded(path, excl):
                continue
            seen.add(path)
            scanned += 1
            try:
                st = os.stat(path)
            except OSError:
                errors += 1
                continue
            rec = baseline.get(path)
            if rec is None:
                digest = sha256_file(path, max_bytes=max_size)
                if digest:
                    changes.append(ChangeRecord(
                        path, "ADDED", None,
                        FileRecord(path, st.st_size, st.st_mtime, digest)))
                continue
            quick_same = (
                rec["size"] == st.st_size
                and abs(rec["mtime"] - st.st_mtime) < 1.5
            )
            if not full and quick_same:
                continue
            digest = sha256_file(path, max_bytes=max_size)
            if digest and digest != rec["sha256"]:
                changes.append(ChangeRecord(
                    path, "MODIFIED",
                    FileRecord(path, rec["size"], rec["mtime"], rec["sha256"]),
                    FileRecord(path, st.st_size, st.st_mtime, digest)))
            elif digest is None:
                errors += 1

        for path, rec in baseline.items():
            if path not in seen and not path_excluded(path, excl):
                changes.append(ChangeRecord(
                    path, "DELETED",
                    FileRecord(path, rec["size"], rec["mtime"], rec["sha256"]),
                    None))

        added = [c for c in changes if c.change == "ADDED"]
        modified = [c for c in changes if c.change == "MODIFIED"]
        deleted = [c for c in changes if c.change == "DELETED"]

        self.db.upsert_baseline([c.new for c in added + modified])
        self.db.remove_baseline([c.path for c in deleted])

        stats = {
            "started": started,
            "files_scanned": scanned,
            "added": len(added),
            "modified": len(modified),
            "deleted": len(deleted),
            "errors": errors,
        }
        self.db.finish_scan(scan_id, stats)
        self.db.set_meta("last_scan", str(started))
        self.db.set_meta("baseline_fingerprint", self.db.baseline_fingerprint())
        self.scan_count += 1

        self._emit(changes, stats)
        return changes

    # -- instant verification (real-time FIM) -----------------------------
    def _process_path_now(self, path: str,
                          ts: Optional[float] = None) -> Optional[ChangeRecord]:
        """Verify a single path immediately and alert if it changed.

        Used by the real-time monitor. Updates the baseline so the next
        periodic sweep will not re-detect the same change (plus a 30 s
        dedup window protects against sweep/realtime races).
        """
        path = self._norm(path)
        excl = self._exclude()
        if path_excluded(path, excl):
            return None
        row = self.db.get_baseline_row(path)
        max_size = int(self.config.get("max_file_size_mb", 100)) * 1024 * 1024

        try:
            st = os.stat(path)
        except OSError:
            st = None

        if st is None:
            if row is None:
                return None
            old = FileRecord(path, row["size"], row["mtime"], row["sha256"])
            change = ChangeRecord(path, "DELETED", old, None, source="realtime")
            self.db.remove_baseline([path])
        else:
            digest = sha256_file(path, max_bytes=max_size)
            if digest is None:
                return None
            rec = FileRecord(path, st.st_size, st.st_mtime, digest)
            if row is None:
                change = ChangeRecord(path, "ADDED", None, rec, source="realtime")
                self.db.upsert_baseline([rec])
            elif digest != row["sha256"]:
                old = FileRecord(path, row["size"], row["mtime"], row["sha256"])
                change = ChangeRecord(path, "MODIFIED", old, rec, source="realtime")
                self.db.upsert_baseline([rec])
            else:
                return None  # rewritten with identical content — no change

        self._emit_single(change, ts=ts)
        return change

    # -- alerting ---------------------------------------------------------
    def _emit_single(self, change: ChangeRecord,
                     ts: Optional[float] = None) -> Optional[Alert]:
        """Emit one change as an alert; deduped per (path, change) within 30 s."""
        ts = ts if ts is not None else now()
        key = (change.path, change.change)
        if ts - self._recent_alerts.get(key, 0.0) < DEDUP_WINDOW:
            return None
        self._recent_alerts[key] = ts
        if len(self._recent_alerts) > 5000:
            cutoff = ts - DEDUP_WINDOW * 10
            self._recent_alerts = {
                k: v for k, v in self._recent_alerts.items() if v > cutoff
            }
        detail = {
            "path": change.path,
            "change": change.change,
            "old": change.old.to_dict() if change.old else None,
            "new": change.new.to_dict() if change.new else None,
            "source": change.source,
        }
        alert = Alert(
            timestamp=ts,
            severity=SEV_BY_CHANGE.get(change.change, "LOW"),
            category="FIM",
            event_type=f"file_{change.change.lower()}",
            title=f"{change.change.title()}: {change.path}",
            details=detail,
        )
        self.db.add_alert(alert)
        self.bus.post(ev.ALERT, alert)
        self._register_burst(1, ts=ts)
        log.info("[%s|%s] %s", change.source, change.change, change.path)
        return alert

    def _emit(self, changes: List[ChangeRecord], stats: dict) -> None:
        emitted = sum(1 for c in changes if self._emit_single(c) is not None)
        self.bus.post(ev.SCAN_FINISHED, {"stats": stats, "changes": changes})
        log.info("Scan done: %s files, %d change alerts, +%d/-%d/~%d in %.1fs",
                 stats["files_scanned"], emitted, stats["added"],
                 stats["deleted"], stats["modified"], now() - stats["started"])

    def _register_burst(self, change_count: int, ts: Optional[float] = None) -> None:
        """Sliding-window mass-modification detector (ransomware heuristic)."""
        ts = ts if ts is not None else now()
        window = max(5, int(self.config.get("burst_window_seconds", 60)))
        threshold = max(3, int(self.config.get("burst_threshold", 15)))
        cooldown = max(30, int(self.config.get("burst_cooldown_seconds", 300)))

        self._recent.append((ts, change_count))
        while self._recent and ts - self._recent[0][0] > window:
            self._recent.popleft()
        total = sum(cnt for _, cnt in self._recent)
        if total < threshold or (ts - self._last_burst) < cooldown:
            return
        self._last_burst = ts
        self._recent.clear()
        alert = Alert(
            timestamp=ts,
            severity="CRITICAL",
            category="FIM",
            event_type="file_burst",
            title=(f"Ransomware-like mass modification: {total} files "
                   f"changed within {window}s"),
            details={"total_changes": total, "window_seconds": window,
                     "recommendation": "Isolate host, check backups, review recent processes."},
        )
        self.db.add_alert(alert)
        self.bus.post(ev.ALERT, alert)
        log.critical("Mass-modification burst: %d files / %ds", total, window)

    # -- helpers ----------------------------------------------------------
    def last_scan_str(self) -> str:
        raw = self.db.get_meta("last_scan")
        return ts_str(float(raw)) if raw else "never"
