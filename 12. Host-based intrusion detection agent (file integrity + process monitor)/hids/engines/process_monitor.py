"""Process monitor engine: psutil telemetry + rule evaluation + alerting."""

import logging
import threading
import time
from typing import List, Optional

import psutil

from ..core import events as ev
from ..core.models import Alert, ProcessInfo, highest_severity
from ..core.utils import now, ts_str
from .rules import evaluate_process

log = logging.getLogger("hids.process")


class ProcessEngine(threading.Thread):
    def __init__(self, config, db, bus):
        super().__init__(name="process-engine", daemon=True)
        self.config = config
        self.db = db
        self.bus = bus
        self.stop_event = threading.Event()
        self.latest: List[ProcessInfo] = []
        self.known: dict = {}  # pid -> (name, create_time)
        self.suspicious_count = 0
        self._alerted: dict = {}  # (rule_id, name) -> ts of last alert

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        log.info("Process engine started (poll=%ss)", self.config.get("process_poll_seconds"))
        self.bus.post(ev.STATUS, {"engine": "process", "running": True})
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("Process tick failed")
            self.stop_event.wait(max(2, int(self.config.get("process_poll_seconds", 10))))
        self.bus.post(ev.STATUS, {"engine": "process", "running": False})
        log.info("Process engine stopped")

    # -- telemetry --------------------------------------------------------
    def snapshot(self) -> List[ProcessInfo]:
        procs: List[ProcessInfo] = []
        for p in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username",
             "cpu_percent", "memory_percent", "create_time"]
        ):
            try:
                info = p.info
                procs.append(ProcessInfo(
                    pid=info["pid"],
                    ppid=info["ppid"] or 0,
                    name=info["name"] or "?",
                    exe=info["exe"] or "",
                    cmdline=list(info["cmdline"] or []),
                    user=info["username"] or "",
                    cpu=float(info["cpu_percent"] or 0.0),
                    mem=float(info["memory_percent"] or 0.0),
                    create_time=info["create_time"],
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        # Resolve parent names from our own snapshot (cheap, no extra syscalls).
        names = {p.pid: p.name for p in procs}
        for p in procs:
            p.parent_name = names.get(p.ppid)
        return procs

    def tick(self) -> List[ProcessInfo]:
        procs = self.snapshot()
        self.latest = procs
        blacklist = {b.lower() for b in (self.config.get("process_blacklist") or [])}
        alert_on_new = bool((self.config.get("process_rules") or {}).get("alert_on_new_process"))

        suspicious = 0
        for p in procs:
            hits = evaluate_process(p, blacklist)
            p.suspicious = bool(hits)
            p.reasons = [f"{sev}: {reason} ({rid})" for rid, sev, reason in hits]
            if p.suspicious:
                suspicious += 1
                self._alert_rules(p, hits)
            elif alert_on_new and p.pid not in self.known:
                self._alert_new_process(p)

        self.known = {
            p.pid: (p.name, p.create_time) for p in procs
        }
        self.suspicious_count = suspicious
        self.bus.post(ev.PROCESS_SNAPSHOT, {"procs": procs, "timestamp": now()})
        return procs

    # -- alerting ---------------------------------------------------------
    def _cooldown_ok(self, key, ts: float) -> bool:
        cooldown = max(60, int(self.config.get("process_alert_cooldown_seconds", 900)))
        last = self._alerted.get(key, 0.0)
        if (ts - last) < cooldown:
            return False
        self._alerted[key] = ts
        return True

    def _alert_rules(self, p: ProcessInfo, hits) -> None:
        ts = now()
        fresh = [h for h in hits if self._cooldown_ok((h[0], p.name.lower()), ts)]
        if not fresh:
            return
        severity = highest_severity(h[1] for h in fresh)
        alert = Alert(
            timestamp=ts,
            severity=severity,
            category="PROCESS",
            event_type="suspicious_process",
            title=f"Suspicious process: {p.name} (PID {p.pid})",
            details={
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "exe": p.exe,
                "cmdline": p.cmdline_str,
                "user": p.user,
                "parent": p.parent_name,
                "hits": [{"rule": rid, "severity": sev, "reason": reason}
                         for rid, sev, reason in fresh],
            },
        )
        self.db.add_alert(alert)
        self.bus.post(ev.ALERT, alert)
        log.warning("%s — %s (pid=%d)", severity, alert.title, p.pid)

    def _alert_new_process(self, p: ProcessInfo) -> None:
        alert = Alert(
            timestamp=now(),
            severity="INFO",
            category="PROCESS",
            event_type="new_process",
            title=f"New process: {p.name} (PID {p.pid})",
            details={"pid": p.pid, "name": p.name, "exe": p.exe,
                     "cmdline": p.cmdline_str, "user": p.user},
        )
        self.db.add_alert(alert)
        self.bus.post(ev.ALERT, alert)

    # -- actions ----------------------------------------------------------
    @staticmethod
    def kill(pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            log.warning("Terminated process pid=%d", pid)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            log.error("Kill failed for pid=%d: %s", pid, exc)
            return False

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def started_str(p: ProcessInfo) -> str:
        try:
            return ts_str(p.create_time) if p.create_time else "-"
        except (OverflowError, OSError, ValueError):
            return "-"
