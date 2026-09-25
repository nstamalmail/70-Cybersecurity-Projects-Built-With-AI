"""WebFuzzer main window: controller, toolbar, tabs, event loop wiring.

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
from app.core.engine import FuzzEngine
from app.core.injector import discover_injection_points
from app.core.models import InjectionPoint, ScanConfig, now_iso
from app.gui.findings_tab import FindingsTab
from app.gui.payloads_tab import PayloadsTab
from app.gui.reports_tab import ReportsTab
from app.gui.scan_tab import ScanTab
from app.gui.settings_tab import SettingsTab
from app.gui.target_tab import TargetTab
from app.gui.widgets import apply_theme
from app.storage.database import Database
from app.utils.settings import Settings
from app.utils.state import StateStore

POLL_MS = 80


class WebFuzzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.db = Database()
        self.settings = Settings()
        self.state = StateStore()
        self.events: "queue.Queue" = queue.Queue()
        self.engine: FuzzEngine | None = None
        self.current_scan_id: int | None = None
        self.current_findings: list = []
        self._paused = False

        apply_theme(root)
        root.title(f"{APP_NAME} — Web App Fuzzer for Input Validation Testing (v{__version__})")
        root.geometry("1280x820")
        root.minsize(1024, 700)

        self._build_toolbar()
        self._build_tabs()
        self._wire_callbacks()

        self._log(f"{APP_NAME} started. Load last configuration; "
                  "re-confirm authorization before scanning.")
        self.state.log_memory("GUI session started")
        self._write_state()
        self.settings_tab.refresh_memory(self.state.read_memory())

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    # ------------------------------------------------------------------ build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        title = ttk.Label(bar, text="🛡 " + APP_NAME,
                          font=("Segoe UI", 15, "bold"), foreground="#89b4fa")
        title.pack(side="left")
        ttk.Label(bar, text=" Authorized input-validation fuzzer",
                  foreground="#7f849c").pack(side="left", padx=(8, 0))

        self.btn_refresh = ttk.Button(bar, text="↻ Load & refresh points", command=self._refresh_points)
        self.btn_refresh.pack(side="right", padx=(6, 0))
        self.btn_sample = ttk.Button(bar, text="✨ Load sample config", command=self._load_sample_config)
        self.btn_sample.pack(side="right", padx=(6, 0))
        self.btn_save = ttk.Button(bar, text="💾 Save config", command=self._save_config)
        self.btn_save.pack(side="right", padx=(6, 0))
        self.btn_import_cfg = ttk.Button(bar, text="📂 Import config", command=self._import_config)
        self.btn_import_cfg.pack(side="right", padx=(6, 0))
        self.btn_export_cfg = ttk.Button(bar, text="🗄 Export config", command=self._export_config)
        self.btn_export_cfg.pack(side="right", padx=(6, 0))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.target_tab = TargetTab(self.notebook)
        self.payloads_tab = PayloadsTab(self.notebook)
        self.scan_tab = ScanTab(self.notebook)
        self.findings_tab = FindingsTab(self.notebook)
        self.reports_tab = ReportsTab(self.notebook, db=self.db)
        self.settings_tab = SettingsTab(self.notebook)

        self.notebook.add(self.target_tab, text="  1. Target  ")
        self.notebook.add(self.payloads_tab, text="  2. Payloads  ")
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
        self.scan_tab.set_on_scan(self._start_scan)
        self.scan_tab.set_on_pause(self._pause_scan)
        self.scan_tab.set_on_stop(self._stop_scan)
        self.scan_tab.set_running(False)
        self.reports_tab.on_load_findings = self._load_findings_from_db
        self.reports_tab.on_imported_scan = self._load_findings_from_db
        self.reports_tab.on_memory_log = lambda msg: self.state.log_memory(msg)
        # Keep the preview/points in sync with target edits.
        self.target_tab.url_var.entry.bind("<KeyRelease>", lambda e: self._auto_refresh_points())
        self.target_tab.method_var.bind("<<ComboboxSelected>>", lambda e: self._auto_refresh_points())
        self.target_tab.headers_text.bind("<KeyRelease>", lambda e: self._auto_refresh_points())
        self.target_tab.cookies_text.bind("<KeyRelease>", lambda e: self._auto_refresh_points())
        self.target_tab.body_text.bind("<KeyRelease>", lambda e: self._auto_refresh_points())
        self.target_tab.body_type_var.bind("<<ComboboxSelected>>", lambda e: self._auto_refresh_points())

    # ------------------------------------------------------- config file I/O
    def _export_config(self) -> None:
        """Save the full current configuration to a JSON file."""
        t = self.target_tab.collect()
        p = self.payloads_tab.collect()
        s = self.scan_tab.collect()
        t["injection_points"] = [ip.to_dict() for ip in self.payloads_tab.get_all_points()]
        doc = {"tool": APP_NAME, "version": __version__, "type": "config",
               "target": t, "payloads": p, "scan": s}
        path = filedialog.asksaveasfilename(
            title="Export configuration", defaultextension=".json",
            initialfile="webfuzzer_config.json",
            filetypes=[("JSON config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"Config exported → {path}")
        self.state.log_memory(f"config exported to {os.path.basename(path)}")
        messagebox.showinfo(APP_NAME, f"Configuration exported to:\n{path}")

    def _import_config(self) -> None:
        """Load a configuration JSON (exported here or a sample config)."""
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else get_base_dir()
        path = filedialog.askopenfilename(
            title="Import configuration", initialdir=initial,
            filetypes=[("JSON config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Import failed: {exc}")
            return
        try:
            self._apply_config_doc(doc)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Invalid config file: {exc}")
            return
        self._log(f"Config imported from {os.path.basename(path)}. "
                  "Review the Target tab and re-confirm authorization.")
        self.state.log_memory(f"config imported from {os.path.basename(path)}")

    def _apply_config_doc(self, doc: dict) -> None:
        """Apply an imported config document to the GUI tabs."""
        t = doc.get("target", doc)
        self.target_tab.apply({
            "target_url": t.get("target_url", t.get("url", "")),
            "method": t.get("method", "GET"),
            "headers": t.get("headers", {}),
            "cookies": t.get("cookies", {}),
            "body": t.get("body", ""),
            "body_type": t.get("body_type", "none"),
        })
        p = doc.get("payloads", {})
        if p:
            self.payloads_tab.apply({
                "categories": p.get("categories", []),
                "encodings": p.get("encodings", ["none", "url"]),
                "custom_payloads": p.get("custom_payloads", []),
            })
        s = doc.get("scan", {})
        if s:
            self.scan_tab.apply({k: v for k, v in s.items() if k != "authorized"})
        points = t.get("injection_points") or doc.get("injection_points")
        self.target_tab.update_preview()
        self._refresh_points()
        if points:
            # Overlay manually-saved points (restores user enabled/disabled choices).
            try:
                saved = [InjectionPoint.from_dict(d) for d in points]
            except Exception:
                saved = []
            if saved:
                self.payloads_tab.set_points(saved)
        self.notebook.select(self.target_tab)

    def _load_sample_config(self) -> None:
        """Load the bundled sample config into the GUI (manual upload path)."""
        sample = os.path.join(SAMPLES_DIR, "sample_config.json")
        if not os.path.exists(sample):
            messagebox.showwarning(APP_NAME, f"Sample config not found:\n{sample}")
            return
        try:
            with open(sample, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self._apply_config_doc(doc)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Could not load sample config: {exc}")
            return
        self._log("Sample config loaded (samples/sample_config.json). "
                  "Point the URL at your authorized test target.")
        self.state.log_memory("sample config loaded into GUI")

    # ---------------------------------------------------------- gather config
    def _gather_config(self) -> ScanConfig:
        t = self.target_tab.collect()
        p = self.payloads_tab.collect()
        s = self.scan_tab.collect()

        points = self.payloads_tab.get_enabled_points()
        if not points:
            points = discover_injection_points(
                ScanConfig(target_url=t["target_url"], method=t["method"],
                           headers=t["headers"], cookies=t["cookies"],
                           body=t["body"], body_type=t["body_type"]))

        cfg = ScanConfig(
            target_url=t["target_url"], method=t["method"],
            headers=t["headers"], cookies=t["cookies"],
            body=t["body"], body_type=t["body_type"],
            injection_points=points,
            categories=p["categories"], encodings=p["encodings"],
            custom_payloads=p["custom_payloads"],
            threads=s["threads"], delay_ms=s["delay_ms"],
            timeout=s["timeout"], follow_redirects=s["follow_redirects"],
            verify_ssl=s["verify_ssl"], proxy=s["proxy"],
            max_requests=s["max_requests"], time_based=s["time_based"],
            authorized=s["authorized"],
        )
        return cfg

    def _refresh_points(self) -> None:
        t = self.target_tab.collect()
        cfg = ScanConfig(target_url=t["target_url"], method=t["method"],
                         headers=t["headers"], cookies=t["cookies"],
                         body=t["body"], body_type=t["body_type"])
        points = discover_injection_points(cfg)
        self.payloads_tab.set_points(points)
        self.target_tab.update_preview()
        self._write_state()

    # ------------------------------------------------------------ settings
    def _save_config(self) -> None:
        t = self.target_tab.collect()
        p = self.payloads_tab.collect()
        s = self.scan_tab.collect()
        self.settings.update({**t, **p, **s})
        self.settings.save()
        self._log("Configuration saved to settings.json")
        self.state.log_memory("configuration saved")

    def _load_config(self) -> None:
        t = {k: self.settings.get(k) for k in
             ("target_url", "method", "headers", "cookies", "body", "body_type")}
        for k in ("headers", "cookies"):
            if not isinstance(t[k], dict):
                t[k] = {}
        self.target_tab.apply(t)
        p = {k: self.settings.get(k) for k in ("categories", "encodings", "custom_payloads")}
        self.payloads_tab.apply(p)
        s = {k: self.settings.get(k) for k in
             ("threads", "delay_ms", "timeout", "max_requests",
              "follow_redirects", "verify_ssl", "time_based", "proxy")}
        self.scan_tab.apply(s)
        self.target_tab.update_preview()
        self._refresh_points()
        self._log("Last configuration loaded.")

    # -------------------------------------------------------------- scanning
    def _start_scan(self) -> None:
        try:
            cfg = self._gather_config()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_NAME, f"Invalid configuration: {exc}")
            return

        # Validation
        parsed = urlparse(cfg.target_url)
        if not cfg.target_url or parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showwarning(APP_NAME, "Enter a valid target URL "
                                             "(http:// or https://).")
            return
        if not self.scan_tab.collect()["authorized"]:
            messagebox.showwarning(APP_NAME,
                                   "You must confirm authorization before scanning.\n\n"
                                   "Only scan targets you own or have written "
                                   "permission to test.")
            return
        if not cfg.injection_points:
            messagebox.showwarning(APP_NAME, "No enabled injection points. "
                                             "Press 'Load & refresh points'.")
            return
        if not self.payloads_tab.validate():
            return

        self.current_findings = []
        self.findings_tab.clear()
        self.scan_tab.clear_log()
        self.scan_tab.set_running(True)
        self.scan_tab.set_status("Starting…")
        self.btn_refresh.configure(state="disabled")

        # Persist scan header + refresh the reports tab automatically.
        self.current_scan_id = self.db.create_scan(cfg, cfg.target_url)
        self._log(f"Scan #{self.current_scan_id} → {cfg.target_url}")

        self.engine = FuzzEngine(cfg, self.events)
        self.engine.start()
        self._write_state()

    def _pause_scan(self) -> None:
        if not self.engine:
            return
        if self._paused:
            self._resume_scan()
            return
        self.engine.pause()
        self._paused = True
        self.scan_tab.pause_btn.configure(text="▶ Resume")
        self.scan_tab.set_status("Paused")
        self.scan_tab.log("⏸ Paused")
        self._log("Scan paused")

    def _resume_scan(self) -> None:
        if not self.engine:
            return
        self._paused = False
        self.engine.resume()
        self.scan_tab.pause_btn.configure(text="⏸ Pause")
        self.scan_tab.set_status("Running")
        self.scan_tab.log("▶ Resumed")
        self._log("Scan resumed")

    def _stop_scan(self) -> None:
        if self.engine:
            self.engine.stop()
            self.scan_tab.set_status("Stopping… (workers drain)")
            self.scan_tab.log("⏹ Stop requested")

    def _on_scan_finished(self) -> None:
        self.scan_tab.set_running(False)
        self.scan_tab.pause_btn.configure(text="⏸ Pause")
        self._paused = False
        self.btn_refresh.configure(state="normal")
        self.scan_tab.set_status("Finished")
        if self.engine:
            st = self.engine.stats
            self.scan_tab.set_stats(st["requests"], st["errors"], st["findings"])
            if self.current_scan_id is not None:
                self.db.finish_scan(self.current_scan_id, st["requests"],
                                    st["findings"], st["errors"])
            self.state.log_memory(
                f"scan #{self.current_scan_id} finished: target={self.engine.config.target_url}, "
                f"requests={st['requests']}, findings={st['findings']}, errors={st['errors']}")
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
    def _load_findings_from_db(self, scan_id: int, findings: list) -> None:
        self.current_findings = list(findings)
        self.findings_tab.set_findings(findings)
        self.notebook.select(self.findings_tab)
        self._log(f"Loaded {len(findings)} findings from scan #{scan_id}.")

    def _write_state(self) -> None:
        st = self.engine.stats if self.engine else {}
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": "running" if (self.engine and self.engine.running) else "idle",
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
        if self.engine and self.engine.running:
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
    app = WebFuzzerApp(root)
    # Load last config after first poll so controls exist.
    root.after(120, app._load_config)
    root.mainloop()
    return 0
