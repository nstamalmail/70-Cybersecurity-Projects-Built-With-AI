"""Wires ingest → normalize → correlate → store → notify.

One processing thread consumes the raw queue so correlation ordering is
deterministic; the GUI receives display items over a separate queue and never
touches pipeline internals directly.
"""
from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable, Optional

from .events import Alert, NormalizedEvent, RawEvent
from .ingest import SourceConfig, SourceManager
from .normalize import Normalizer
from .notifiers import build_notifiers, Notifier
from .rules import CorrelationEngine, Rule
from .storage import Storage

log = logging.getLogger("siem")

EventCb = Callable[[NormalizedEvent], None]
AlertCb = Callable[[Alert], None]
LogCb = Callable[[str], None]


class Pipeline:
    def __init__(self, storage: Storage, config: dict[str, Any],
                 on_event: Optional[EventCb] = None,
                 on_alert: Optional[AlertCb] = None,
                 on_log: Optional[LogCb] = None,
                 alert_log_path: Optional[str] = None,
                 notifiers: Optional[list[Notifier]] = None) -> None:
        self.storage = storage
        self.config = config
        self.on_event = on_event
        self.on_alert = on_alert
        self.on_log = on_log
        self.alert_log_path = alert_log_path

        self.raw_q: "queue.Queue[RawEvent]" = queue.Queue(
            maxsize=int(config.get("raw_queue_size", 10000))
        )
        self.stop_evt = threading.Event()
        self.sources = SourceManager(
            self.raw_q, self.stop_evt,
            poll_interval=float(config.get("poll_interval", 0.5)),
        )
        self.normalizer = Normalizer()
        self.engine = CorrelationEngine(storage.get_rules(), self._fire_alert)

        self.stats = {"processed": 0, "normalized": 0, "dropped": 0, "alerts": 0}
        self.notifiers: list[Notifier] = list(notifiers or [])
        self._thread = threading.Thread(target=self._loop, name="pipeline", daemon=True)

    # ------------------------------------------------------------------ logs
    def _log(self, msg: str) -> None:
        line = f"{_now_str()}  {msg}"
        log.info(msg)
        if self.on_log:
            self.on_log(line)

    # --------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self._log(f"Pipeline started (rules: {len(self.engine.rules)} enabled)")
        self._thread.start()
        self.sources.start_source_all()

    def stop(self) -> None:
        self.stop_evt.set()
        self.sources.stop_all()
        self._thread.join(timeout=3.0)
        self._log("Pipeline stopped")

    # ------------------------------------------------------------- processing
    def _loop(self) -> None:
        while not self.stop_evt.is_set():
            try:
                raw = self.raw_q.get(timeout=0.2)
            except queue.Empty:
                continue
            self.stats["processed"] += 1
            try:
                ev = self.normalizer.normalize(raw)
            except Exception as exc:
                self.stats["dropped"] += 1
                self._log(f"normalize error: {exc}")
                continue
            self.stats["normalized"] += 1
            try:
                self.storage.insert_event(ev)
            except Exception as exc:
                self._log(f"store error: {exc}")
            try:
                self.engine.process(ev)
            except Exception as exc:
                self._log(f"correlate error: {exc}")
            if self.on_event:
                try:
                    self.on_event(ev)
                except Exception:
                    pass

    def _fire_alert(self, alert: Alert) -> None:
        self.stats["alerts"] += 1
        try:
            self.storage.insert_alert(alert)
        except Exception as exc:
            self._log(f"alert store error: {exc}")
        line = (f"{_now_str()} [{alert.severity.upper()}] {alert.rule_name} "
                f"(key={alert.group_key}) {alert.summary}")
        if self.alert_log_path:
            try:
                with open(self.alert_log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass
        self._log(f"[ALERT] {line}")
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass
        # Outbound alert notifiers run after the alert is persisted and the UI
        # callback has been given a chance. Each notifier is called in its own
        # try/except so a single misconfigured one cannot kill the pipeline or
        # suppress the alert.
        for n in self.notifiers:
            try:
                n.notify(alert)
            except Exception as exc:
                self._log(f"notifier error ({type(n).__name__}): {exc}")

    def attach_notifiers(self, notifiers: list[Notifier]) -> None:
        """Swap the active notifier set at runtime (e.g. after a config reload)."""
        self.notifiers = list(notifiers)
        self._log(f"Notifiers updated ({len(self.notifiers)} configured)")

    # ----------------------------------------------------------- rule changes
    def reload_rules(self) -> None:
        self.engine.reload_rules(self.storage.get_rules())
        self._log(f"Rules reloaded ({len(self.engine.rules)} enabled)")

    # -------------------------------------------------------------- ingest API
    def ingest_text(self, text: str, source_name: str = "manual") -> int:
        n = self.sources.ingest_text(text, source_name)
        self._log(f"Manually ingested {n} line(s) from '{source_name}'")
        return n

    def add_source(self, cfg: SourceConfig) -> None:
        self.sources.add_source(cfg)
        self._log(f"Source added: {cfg.name} ({cfg.describe()})")

    def remove_source(self, source_id: str) -> None:
        cfg = next((s for s in self.sources.sources() if s.id == source_id), None)
        self.sources.remove_source(source_id)
        if cfg:
            self._log(f"Source removed: {cfg.name}")

    def start_source(self, source_id: str) -> None:
        self.sources.start_source(source_id)

    def stop_source(self, source_id: str) -> None:
        self.sources.stop_source(source_id)


def _now_str() -> str:
    import time
    return time.strftime("%H:%M:%S", time.localtime())