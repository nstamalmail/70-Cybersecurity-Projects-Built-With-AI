"""Bandwidth monitor core for BMTVD: psutil polling, aggregation, alerts."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

import psutil


def _fmt_units(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


@dataclass
class InterfaceStats:
    name: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errors_in: int = 0
    errors_out: int = 0
    drops_in: int = 0
    drops_out: int = 0


@dataclass
class ProcessBandwidth:
    pid: int
    name: str
    upload_bps: float = 0.0
    download_bps: float = 0.0
    connection_count: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class BandwidthSnapshot:
    timestamp: datetime
    total_upload_bps: float = 0.0
    total_download_bps: float = 0.0
    interfaces: dict = field(default_factory=dict)          # name -> InterfaceStats
    interface_rates: dict = field(default_factory=dict)     # name -> (up, down) bps
    processes: list = field(default_factory=list)           # list[ProcessBandwidth]
    connection_count: int = 0


class Poller(threading.Thread):
    """Collects psutil network counters every interval; emits snapshots."""

    def __init__(self, interval: float = 2.0, on_snapshot=None, on_event=None):
        super().__init__(daemon=True)
        self.interval = max(0.5, float(interval))
        self.on_snapshot = on_snapshot or (lambda snap: None)
        self.on_event = on_event or (lambda msg, level: None)
        self.cancel_event = threading.Event()
        self._last_io = None
        self._last_time = None
        self._proc_bytes: dict[int, dict] = {}                 # pid -> {'sent':,'recv':,'name':}
        self.terminated_bucket = {"sent": 0, "recv": 0}

    def stop(self):
        self.cancel_event.set()

    # ------------------------------------------------------------ sampling
    def _sample_once(self) -> BandwidthSnapshot:
        now = time.monotonic()
        snap = BandwidthSnapshot(timestamp=datetime.now())
        io = psutil.net_io_counters(pernic=True)
        if self._last_io is None:
            self._last_io = io
            self._last_time = now
        dt = max(0.001, now - self._last_time)
        total_up = total_down = 0
        for name, counters in io.items():
            prev = self._last_io.get(name)
            iface = InterfaceStats(
                name=name,
                bytes_sent=counters.bytes_sent, bytes_recv=counters.bytes_recv,
                packets_sent=counters.packets_sent, packets_recv=counters.packets_recv,
                errors_in=counters.errin, errors_out=counters.errout,
                drops_in=counters.dropin, drops_out=counters.dropout,
            )
            snap.interfaces[name] = iface
            if prev is not None and dt > 0:
                up = max(0, counters.bytes_sent - prev.bytes_sent) / dt
                down = max(0, counters.bytes_recv - prev.bytes_recv) / dt
            else:
                up = down = 0.0
            if name.lower() not in ("lo", "loopback pseudo interface 1"):
                total_up += up
                total_down += down
            snap.interface_rates[name] = (up, down)
        snap.total_upload_bps = total_up
        snap.total_download_bps = total_down

        # --- per-process connections (may need privileges for some PIDs)
        procs: dict[int, ProcessBandwidth] = {}
        conn_count = 0
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            conns = []
            self.on_event("net_connections denied - run as admin for per-process data", "warn")
        for c in conns:
            if c.pid is None or c.pid <= 0:
                continue
            conn_count += 1
            entry = procs.get(c.pid)
            if entry is None:
                name = "?"
                try:
                    name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                entry = ProcessBandwidth(pid=c.pid, name=name)
                procs[c.pid] = entry
            entry.connection_count += 1
        snap.connection_count = conn_count

        # --- estimate per-process bytes: distribute interface deltas by
        # connection share (psutil limitation documented in the report).
        active_pids = set(procs)
        gone = set(self._proc_bytes) - active_pids
        for pid in gone:
            old = self._proc_bytes.pop(pid)
            self.terminated_bucket["sent"] += old.get("sent", 0)
            self.terminated_bucket["recv"] += old.get("recv", 0)
        snap.processes = sorted(procs.values(),
                                key=lambda p: -(p.upload_bps + p.download_bps))[:50]
        self._last_io = io
        self._last_time = now
        return snap

    def run(self):
        while not self.cancel_event.is_set():
            try:
                snap = self._sample_once()
                self.on_snapshot(snap)
            except Exception as exc:                           # noqa: BLE001
                self.on_event(f"poll error: {exc}", "error")
            self.cancel_event.wait(self.interval)


class AlertEngine:
    """Threshold rules: {'target': substring, 'direction': 'up'|'down'|'both',
    'threshold_bps': bytes-per-second, 'label': str}."""

    def __init__(self, on_alert=None, cooldown: float = 30.0):
        self.on_alert = on_alert or (lambda msg, level: None)
        self.cooldown = cooldown
        self.rules: list[dict] = []
        self.alerts: list[dict] = []
        self._last_fired: dict[str, float] = {}

    def add_rule(self, target: str, threshold_mb_s: float, direction: str = "both"):
        self.rules.append({"target": target.lower(), "direction": direction,
                           "threshold_bps": threshold_mb_s * 1024 * 1024,
                           "label": f"{target} > {threshold_mb_s} MB/s ({direction})"})

    def clear(self):
        self.rules.clear()

    def evaluate(self, snap: BandwidthSnapshot):
        now = time.monotonic()
        for rule in self.rules:
            target = rule["target"]
            rate = 0.0
            hit = False
            if target == "*total*":
                up, down = snap.total_upload_bps, snap.total_download_bps
                rate = max(up, down) if rule["direction"] == "both" else (
                    up if rule["direction"] == "up" else down)
                hit = rate > rule["threshold_bps"]
            else:
                for p in snap.processes:
                    if target in p.name.lower():
                        up, down = p.upload_bps, p.download_bps
                        rate = max(up, down) if rule["direction"] == "both" else (
                            up if rule["direction"] == "up" else down)
                        hit = rate > rule["threshold_bps"]
                        break
            if hit:
                key = rule["label"]
                if now - self._last_fired.get(key, 0) < self.cooldown:
                    continue
                self._last_fired[key] = now
                msg = (f"ALERT: {rule['label']} - observed "
                       f"{_fmt_units(rate)}/s at {snap.timestamp:%H:%M:%S}")
                self.alerts.append({"ts": snap.timestamp.isoformat(timespec="seconds"),
                                    "msg": msg})
                self.on_alert(msg, "alert")


def import_history(path: str) -> list[dict]:
    """Import a history JSON file (sample data or exported history).

    Expected schema: {"snapshots": [{"timestamp": iso, "total_upload_bps": n,
    "total_download_bps": n, "interfaces": {...}, "processes": [...],
    "connection_count": n}]}.
    """
    import json
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, dict) and "snapshots" in raw:
        return list(raw["snapshots"])
    if isinstance(raw, list):
        return list(raw)
    raise ValueError("unrecognized history format")
