"""Main application window: shell, toolbar, tabs, event pump, logging."""

import logging
import logging.handlers
import queue as queue_mod
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from .. import APP_NAME, __version__
from ..core import events as ev
from ..core.config import Config
from ..core.database import Database
from ..core.events import EventBus
from ..core.utils import default_data_dir, is_frozen, ts_str
from ..engines.fim import FimEngine
from ..engines.process_monitor import ProcessEngine
from .tabs.alerts_tab import AlertsTab
from .tabs.dashboard import DashboardTab
from .tabs.fim_tab import FimTab
from .tabs.logs_tab import LogsTab
from .tabs.process_tab import ProcessTab
from .tabs.settings_tab import SettingsTab
from .widgets import BG, ACCENT, SEV_COLORS


class BusLogHandler(logging.Handler):
    """Forwards engine log records to the GUI event bus."""

    def __init__(self, bus: EventBus):
        super().__init__()
        self.bus = bus
        self.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                                            datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            self.bus.post(ev.LOG, {"line": self.format(record)})
        except Exception:
            pass


def setup_logging(data_dir) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    file_h = logging.handlers.RotatingFileHandler(
        data_dir / "hids.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    file_h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    root.addHandler(file_h)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)


class HidsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — Host Intrusion Detection Agent v{__version__}")
        self.geometry("1240x780")
        self.minsize(1000, 640)

        self.data_dir = default_data_dir()
        setup_logging(self.data_dir)
        self.log = logging.getLogger("hids.app")

        self.bus = EventBus()
        self.ui_queue = self.bus.subscribe()
        self.bus_log_handler = BusLogHandler(self.bus)
        logging.getLogger("hids").addHandler(self.bus_log_handler)

        self.config = Config(self.data_dir)
        self.db = Database(self.data_dir)
        self.fim = FimEngine(self.config, self.db, self.bus)
        self.proc = ProcessEngine(self.config, self.db, self.bus)
        self.monitoring = False

        self._build_style()
        self._build_ui()
        self._check_baseline_tamper()
        self.after(150, self._drain)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.log.info("%s v%s started (data: %s, frozen=%s)",
                      APP_NAME, __version__, self.data_dir, is_frozen())

    # -- UI construction ---------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("CardTitle.TLabel", background="#ffffff",
                        foreground="#7a7a7a", font=("Segoe UI", 8, "bold"))
        style.configure("CardSub.TLabel", background="#ffffff",
                        foreground="#9a9a9a", font=("Segoe UI", 8))
        style.configure("Toolbar.TFrame", background=BG)
        style.configure("Toolbar.TButton", padding=(10, 5))
        style.configure("Status.TLabel", background="#e8ebef", padding=(8, 4))
        style.configure("Treeview", rowheight=22, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        # Toolbar
        bar = ttk.Frame(self, style="Toolbar.TFrame", padding=8)
        bar.pack(fill="x")
        self.start_btn = ttk.Button(bar, text="▶ Start Monitoring",
                                    style="Toolbar.TButton",
                                    command=self.start_monitoring)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="■ Stop Monitoring",
                                   style="Toolbar.TButton",
                                   command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.led = tk.Canvas(bar, width=14, height=14, highlightthickness=0)
        self.led_id = self.led.create_oval(2, 2, 12, 12, fill="#b0b0b0", outline="")
        self.led.pack(side="left", padx=(14, 4))
        self.status_var = tk.StringVar(value="Idle — configure paths, build a baseline, then start monitoring")
        ttk.Label(bar, textvariable=self.status_var, background=BG).pack(side="left")
        ttk.Label(bar, text=f"{APP_NAME} v{__version__}", background=BG,
                  foreground="#888888").pack(side="right")

        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)
        self.tab_dashboard = DashboardTab(self.nb, self)
        self.tab_fim = FimTab(self.nb, self)
        self.tab_processes = ProcessTab(self.nb, self)
        self.tab_alerts = AlertsTab(self.nb, self)
        self.tab_settings = SettingsTab(self.nb, self)
        self.tab_logs = LogsTab(self.nb, self)
        for text, tab in [
            ("Dashboard", self.tab_dashboard), ("File Integrity", self.tab_fim),
            ("Process Monitor", self.tab_processes), ("Alerts", self.tab_alerts),
            ("Settings", self.tab_settings), ("Logs", self.tab_logs),
        ]:
            self.nb.add(tab, text=f" {text} ")

        # Status bar
        status = ttk.Frame(self)
        status.pack(fill="x", side="bottom")
        self.sb_baseline = ttk.Label(status, text="Baseline: —", style="Status.TLabel")
        self.sb_baseline.pack(side="left")
        self.sb_scan = ttk.Label(status, text="Last scan: never", style="Status.TLabel")
        self.sb_scan.pack(side="left", padx=6)
        self.sb_rt = ttk.Label(status, text="Real-time FIM: off", style="Status.TLabel")
        self.sb_rt.pack(side="left", padx=6)
        self.sb_data = ttk.Label(status, text=f"Data: {self.data_dir}",
                                 style="Status.TLabel")
        self.sb_data.pack(side="right")
        self._refresh_statusbar()

    # -- actions -------------------------------------------------------------
    def start_monitoring(self):
        if self.monitoring:
            return
        if self.db.baseline_count() == 0 and not (self.config.get("monitored_paths") or []):
            messagebox.showwarning(
                "Nothing to monitor",
                "Add monitored paths in the File Integrity tab and build a baseline first.\n"
                "Process monitoring can still run — start anyway to enable it.")
        if not self.fim.is_alive():
            self.fim = FimEngine(self.config, self.db, self.bus)
        if not self.proc.is_alive():
            self.proc = ProcessEngine(self.config, self.db, self.bus)
        self.fim.start()
        self.proc.start()
        self.monitoring = True
        self.start_btn["state"] = "disabled"
        self.stop_btn["state"] = "normal"
        self.led.itemconfigure(self.led_id, fill="#2e7d32")
        self.status_var.set("Monitoring active — FIM + process engines running")
        self.log_line("Monitoring started")
        self._refresh_statusbar()

    def stop_monitoring(self):
        if not self.monitoring:
            return
        self.fim.stop()
        self.proc.stop()
        self.monitoring = False
        self.start_btn["state"] = "normal"
        self.stop_btn["state"] = "disabled"
        self.led.itemconfigure(self.led_id, fill="#b0b0b0")
        self.status_var.set("Stopped")
        self.log_line("Monitoring stopped")
        self._refresh_statusbar()

    def _refresh_statusbar(self):
        count = self.db.baseline_count()
        self.sb_baseline["text"] = f"Baseline: {count} files"
        self.sb_scan["text"] = f"Last scan: {self.fim.last_scan_str()}"
        rt = self.monitoring and getattr(self.fim, "realtime_active", False)
        self.sb_rt["text"] = f"Real-time FIM: {'ON' if rt else 'off'}"

    # -- event pump ------------------------------------------------------------
    def _drain(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                self._handle(kind, payload)
        except queue_mod.Empty:
            pass
        self.after(150, self._drain)

    def _handle(self, kind, payload):
        if kind == ev.ALERT:
            self.tab_alerts.add_alert(payload)
            self.tab_dashboard.on_alert(payload)
            self.log_line(f"[ALERT][{payload.severity}] {payload.title}")
        elif kind == ev.LOG:
            self.tab_logs.append(payload["line"])
        elif kind == ev.SCAN_PROGRESS:
            self.tab_fim.on_progress(payload)
        elif kind == ev.SCAN_FINISHED:
            stats = dict(payload.get("stats") or {})
            stats.setdefault("finished_ts", time.time())
            self.tab_fim.on_scan_finished(payload)
            self.tab_dashboard.on_scan()
            self._refresh_statusbar()
        elif kind == ev.PROCESS_SNAPSHOT:
            self.tab_processes.on_snapshot(payload)
        elif kind == ev.STATUS:
            if payload.get("engine") == "fim_realtime":
                self._refresh_statusbar()  # observer may start asynchronously
        elif kind == ev.UI_CALL:
            fn, args = payload
            try:
                fn(*args)
            except Exception:
                self.log.exception("UI call failed")

    # -- helpers ----------------------------------------------------------------
    def log_line(self, message: str) -> None:
        self.tab_logs.append(f"{ts_str(time.time())}  {message}")

    def ui_call(self, fn, *args):
        """Run a callable on the UI thread from any worker thread."""
        self.bus.post(ev.UI_CALL, (fn, args))

    def _check_baseline_tamper(self):
        """Agent self-protection: detect tampering with the baseline DB."""
        stored = self.db.get_meta("baseline_fingerprint")
        if not stored or self.db.baseline_count() == 0:
            return
        current = self.db.baseline_fingerprint()
        if current != stored:
            from ..core.models import Alert
            from ..core.utils import now
            alert = Alert(
                timestamp=now(), severity="CRITICAL", category="SYSTEM",
                event_type="baseline_tampered",
                title="Baseline integrity check FAILED — baseline database may be tampered with",
                details={"stored_fingerprint": stored, "current_fingerprint": current,
                         "recommendation": "Rebuild the baseline from a trusted state."})
            self.db.add_alert(alert)
            self.log.critical("Baseline fingerprint mismatch — possible tampering")

    def _on_close(self):
        if self.monitoring and messagebox.askyesno(
                "Quit", "Monitoring is active. Stop engines and quit?"):
            self.stop_monitoring()
        try:
            self.fim.stop()
            self.proc.stop()
            # give threads a moment to exit
            self.fim.join(timeout=1.5)
            self.proc.join(timeout=1.5)
            self.db.close()
        except Exception:
            pass
        self.destroy()


def run_app() -> None:
    app = HidsApp()
    app.mainloop()
