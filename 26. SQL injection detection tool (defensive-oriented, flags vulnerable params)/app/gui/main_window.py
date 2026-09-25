"""SIDT main window: controller, toolbar, tabs, event loop wiring.

Threading contract: workers push events onto queue.Queue; the main thread polls
via root.after() and applies them to widgets. No cross-thread widget access.
"""

from __future__ import annotations

import json
import os
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_base_dir, get_data_dir
from app.core.engine import ScanEngine
from app.core.http_client import (discover_parameters, parse_cookies_text,
                                  parse_headers_text)
from app.core.models import Parameter, ScanConfig, now_iso
from app.gui.tabs import (FindingsTab, ParametersTab, ReportsTab, ScanTab,
                          SettingsTab, TargetTab)
from app.gui.widgets import apply_theme
from app.storage.database import Database
from app.utils.settings import Settings
from app.utils.state import StateStore

POLL_MS = 80


class SidtApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.db = Database()
        self.settings = Settings()
        self.state = StateStore()
        self.events: "queue.Queue" = queue.Queue()
        self.engine: ScanEngine | None = None
        self.current_scan_id: int | None = None
        self.current_findings: list = []
        self._paused = False

        apply_theme(root)
        root.title(f"{APP_NAME} — SQL Injection Detection Tool "
                   f"(defensive) v{__version__}")
        root.geometry("1280x820")
        root.minsize(1024, 700)

        self._build_toolbar()
        self._build_tabs()
        self._wire_callbacks()

        self._log(f"{APP_NAME} started. Configure a target you are authorized "
                  "to test; safe mode is ON by default.")
        self.state.log_memory("GUI session started")
        self._write_state()
        self.settings_tab.refresh_memory(self.state.read_memory())

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    # ------------------------------------------------------------- settings
    def _save_config(self) -> None:
        t = self.target_tab.collect()
        s = self.scan_tab.collect()
        self.settings.update({**t, **s})
        self.settings.save()
        self._log("Configuration saved to settings.json")
        self.state.log_memory("configuration saved")

    # ------------------------------------------------------------------ build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="🛡 " + APP_NAME, font=("Segoe UI", 15, "bold"),
                  foreground="#89b4fa").pack(side="left")
        ttk.Label(bar, text=" Defensive SQL injection detection",
                  foreground="#7f849c").pack(side="left", padx=(8, 0))

        ttk.Button(bar, text="✨ Load sample config",
                   command=self._load_sample_config).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="💾 Save config",
                   command=self._save_config).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="📂 Import config",
                   command=self._import_config).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="🗄 Export config",
                   command=self._export_config).pack(side="right", padx=(6, 0))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.target_tab = TargetTab(self.notebook)
        self.params_tab = ParametersTab(self.notebook)
        self.scan_tab = ScanTab(self.notebook)
        self.findings_tab = FindingsTab(self.notebook)
        self.reports_tab = ReportsTab(self.notebook, db=self.db)
        self.settings_tab = SettingsTab(self.notebook)

        self.notebook.add(self.target_tab, text="  1. Target  ")
        self.notebook.add(self.params_tab, text="  2. Parameters  ")
        self.notebook.add(self.scan_tab, text="  3. Scan  ")
        self.notebook.add(self.findings_tab, text="  4. Findings  ")
        self.notebook.add(self.reports_tab, text="  5. Reports  ")
        self.notebook.add(self.settings_tab, text="  6. Settings  ")

        base = get_base_dir()
        self.settings_tab.set_paths({
            "Base dir": base,
            "state.md": os.path.join(base, "state.md"),
            "memory.md": os.path.join(base, "memory.md"),
            "settings.json": os.path.join(get_data_dir(), "settings.json"),
            "Database": self.db.path,
            "Samples": SAMPLES_DIR,
        })

    def _wire_callbacks(self) -> None:
        self.scan_tab.on_scan = self._start_scan
        self.scan_tab.on_pause = self._pause_scan
        self.scan_tab.on_stop = self._stop_scan
        self.scan_tab.set_running(False)
        self.target_tab.on_import_parameters = self._import_parameters_path
        self.params_tab.on_import_parameters = self._import_parameters_path
        self.reports_tab.on_load_findings = self._load_findings_from_db
        self.reports_tab.on_imported_scan = self._load_findings_from_db
        self.reports_tab.on_memory_log = lambda msg: self.state.log_memory(msg)

    # -------------------------------------------------------- parameter import
    def _import_parameters_path(self, path: str) -> None:
        """Load manual parameter definitions from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read parameters JSON: {exc}")
            return
        items = doc.get("parameters", doc) if isinstance(doc, dict) else doc
        if not isinstance(items, list):
            messagebox.showwarning(APP_NAME,
                                   "Expected a list of parameters or "
                                   "{\"parameters\": [...]}")
            return
        existing = {p["name"]: p for p in self.params_tab.get_all()}
        for item in items:
            if isinstance(item, dict) and item.get("name"):
                existing[str(item["name"])] = {
                    "location": item.get("location", "query"),
                    "name": str(item["name"]),
                    "value": str(item.get("value", "")),
                    "enabled": bool(item.get("enabled", True)),
                }
        self.params_tab.set_parameters(list(existing.values()))
        self.notebook.select(self.params_tab)
        self._log(f"Parameters imported from {os.path.basename(path)} "
                  f"({len(items)} entries).")
        self.state.log_memory(f"parameters imported from {os.path.basename(path)}")

    # ---------------------------------------------------------- config file I/O
    def _export_config(self) -> None:
        t = self.target_tab.collect()
        s = self.scan_tab.collect()
        t["parameters"] = self.params_tab.get_all()
        doc = {"tool": APP_NAME, "version": __version__, "type": "config",
               "target": t, "scan": s}
        path = filedialog.asksaveasfilename(
            title="Export configuration", defaultextension=".json",
            initialfile="sidt_config.json",
            filetypes=[("JSON config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"Config exported → {path}")
        self.state.log_memory("config exported")

    def _import_config(self) -> None:
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else get_base_dir()
        path = filedialog.askopenfilename(
            title="Import configuration", initialdir=initial,
            filetypes=[("JSON config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self._apply_config_doc(doc)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Invalid config file: {exc}")
            return
        self._log(f"Config imported from {os.path.basename(path)}. "
                  "Re-confirm authorization before scanning.")
        self.state.log_memory("config imported")

    def _apply_config_doc(self, doc: dict) -> None:
        t = doc.get("target", doc)
        self.target_tab.apply(t)
        params = t.get("parameters") or doc.get("parameters")
        if isinstance(params, list):
            self.params_tab.set_parameters(params)
        s = doc.get("scan", {})
        if s:
            self.scan_tab.apply({k: v for k, v in s.items() if k != "authorized"})
        self.notebook.select(self.target_tab)

    def _load_sample_config(self) -> None:
        sample = os.path.join(SAMPLES_DIR, "sample_config.json")
        if not os.path.exists(sample):
            messagebox.showwarning(APP_NAME, f"Sample config not found:\n{sample}")
            return
        try:
            with open(sample, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self._apply_config_doc(doc)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not load sample config: {exc}")
            return
        self._log("Sample config loaded (samples/sample_config.json).")
        self.state.log_memory("sample config loaded into GUI")

    # --------------------------------------------------------------- gather
    def _gather_config(self) -> ScanConfig:
        t = self.target_tab.collect()
        s = self.scan_tab.collect()
        params_raw = self.params_tab.get_all()
        cfg = ScanConfig(
            target_url=t["target_url"], method=t["method"],
            headers=parse_headers_text(t["headers_text"]),
            cookies=parse_cookies_text(t["cookies_text"]),
            body=t["body"], body_type=t["body_type"],
            techniques=s["techniques"], safe_mode=s["safe_mode"],
            delay_ms=s["delay_ms"], timeout=s["timeout"],
            time_threshold_s=s["time_threshold_s"],
            verify_ssl=s["verify_ssl"], proxy=s["proxy"],
            authorized=s["authorized"],
        )
        if params_raw:
            cfg.parameters = [Parameter(
                location=p["location"], name=p["name"], value=p["value"],
                enabled=p["enabled"]) for p in params_raw]
        else:
            cfg.parameters = discover_parameters(cfg)
        return cfg

    # --------------------------------------------------------------- scanning
    def _start_scan(self) -> None:
        try:
            cfg = self._gather_config()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Invalid configuration: {exc}")
            return
        parsed = urlparse(cfg.target_url)
        if not cfg.target_url or parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showwarning(APP_NAME,
                                   "Enter a valid target URL (http:// or https://).")
            return
        if not cfg.authorized:
            messagebox.showwarning(APP_NAME,
                                   "You must confirm authorization before scanning.\n\n"
                                   "Only scan targets you own or have written "
                                   "permission to test.")
            return
        if not cfg.parameters:
            messagebox.showwarning(APP_NAME,
                                   "No parameters to test. Enter a URL with query "
                                   "parameters or import parameters JSON.")
            return
        if not cfg.techniques:
            messagebox.showwarning(APP_NAME, "Select at least one technique.")
            return
        if cfg.safe_mode and set(cfg.techniques) - {"error", "boolean"}:
            messagebox.showwarning(APP_NAME,
                                   "Safe mode allows only error-based and "
                                   "boolean-based techniques.")
            return

        self.current_findings = []
        self.findings_tab.clear()
        self.scan_tab.clear_log()
        self.scan_tab.set_running(True)
        self.scan_tab.set_status("Starting…")

        self.current_scan_id = self.db.create_scan(cfg, cfg.target_url,
                                                   safe_mode=cfg.safe_mode)
        self._log(f"Scan #{self.current_scan_id} → {cfg.target_url}")

        self.engine = ScanEngine(cfg, self.events)
        self.engine.start()
        self._write_state()

    def _pause_scan(self) -> None:
        if not self.engine:
            return
        self.scan_tab.log("⏸ Pause/resume is applied on the next request batch.")

    def _stop_scan(self) -> None:
        if self.engine:
            self.engine.stop()
            self.scan_tab.set_status("Stopping… (workers drain)")
            self.scan_tab.log("⏹ Stop requested")

    def _on_scan_finished(self) -> None:
        self.scan_tab.set_running(False)
        st = self.engine.stats if self.engine else {}
        self.scan_tab.set_status("Finished")
        self.scan_tab.set_stats(st.get("requests", 0), st.get("errors", 0),
                                st.get("findings", 0), st.get("parameters", 0))
        if self.current_scan_id is not None:
            self.db.finish_scan(self.current_scan_id,
                                st.get("parameters", 0), st.get("requests", 0),
                                st.get("findings", 0), st.get("errors", 0),
                                self.engine.waf if self.engine else "")
        self.state.log_memory(
            f"scan #{self.current_scan_id} finished: "
            f"requests={st.get('requests', 0)}, findings={st.get('findings', 0)}, "
            f"errors={st.get('errors', 0)}")
        if self.engine:
            self.engine.mark_done()
        self._write_state()
        self.reports_tab.refresh()
        self.notebook.select(self.findings_tab)

    # ------------------------------------------------------------ event loop
    def _poll_events(self) -> None:
        try:
            while True:
                ev = self.events.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._poll_events)

    def _handle_event(self, ev: dict) -> None:
        typ = ev["type"]
        if typ == "status":
            self.scan_tab.set_status(ev["message"])
        elif typ == "log":
            self.scan_tab.log(ev["message"])
        elif typ == "progress":
            self.scan_tab.set_progress(ev["done"], ev["total"])
        elif typ == "finding":
            f = ev["finding"]
            if self.current_scan_id is not None:
                f.scan_id = self.current_scan_id
                f.id = self.db.insert_finding(self.current_scan_id, f)
            self.current_findings.append(f.to_dict())
            self.findings_tab.add_finding(f.to_dict())
            st = self.engine.stats if self.engine else {}
            self.scan_tab.set_stats(st.get("requests", 0), st.get("errors", 0),
                                    st.get("findings", 0))
            self.scan_tab.log(f"⚠ {f.summary()}", "warn")
            self._write_state()
        elif typ == "scan_finished":
            self._on_scan_finished()

    # ---------------------------------------------------------------- helpers
    def _load_last_config(self) -> None:
        """Restore last saved settings into the tabs."""
        t = {k: self.settings.get(k) for k in
             ("target_url", "method", "headers_text", "cookies_text",
              "body", "body_type")}
        self.target_tab.apply(t)
        s = {k: self.settings.get(k) for k in
             ("safe_mode", "techniques", "delay_ms", "timeout",
              "time_threshold_s", "proxy", "verify_ssl")}
        self.scan_tab.apply(s)
        self._log("Last configuration loaded.")

    def _load_findings_from_db(self, scan_id: int, findings: list) -> None:
        self.current_findings = list(findings)
        self.findings_tab.set_findings(findings)
        self.notebook.select(self.findings_tab)
        self._log(f"Loaded {len(findings)} findings from scan #{scan_id}.")

    def _write_state(self) -> None:
        st = self.engine.stats if self.engine else {}
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": "running" if (self.engine and self.engine.is_alive()) else "idle",
            "Last activity": now_iso(),
            "Current scan": f"#{self.current_scan_id}" if self.current_scan_id else "none",
            "Requests": st.get("requests", 0),
            "Errors": st.get("errors", 0),
            "Findings": st.get("findings", 0),
            "state.md": "live snapshot (this file)",
            "memory.md": "append-only history",
        })

    def _log(self, line: str) -> None:
        self.scan_tab.log(f"[app] {line}")

    # ----------------------------------------------------------------- close
    def _on_close(self) -> None:
        if self.engine and self.engine.is_alive():
            if not messagebox.askyesno(APP_NAME, "A scan is running. Stop and exit?"):
                return
            self.engine.stop()
        self.settings.save()
        self.state.log_memory("GUI session ended")
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": "closed",
            "Last activity": now_iso(),
        })
        try:
            self.db.close()
        finally:
            self.root.destroy()


def run_gui() -> int:
    root = tk.Tk()
    app = SidtApp(root)
    root.after(120, app._load_last_config)
    root.mainloop()
    return 0
