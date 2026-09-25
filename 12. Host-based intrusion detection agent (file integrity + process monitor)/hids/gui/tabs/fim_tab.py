"""File Integrity tab: monitored paths, baseline build, manual verify."""

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ...core.utils import human_size, ts_str
from ..widgets import SEV_COLORS, make_tree


class FimTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        self._busy = False
        self._build()
        self.reload_paths()
        self.refresh_baseline_info()

    # -- UI ----------------------------------------------------------------
    def _build(self):
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True)

        # Left: monitored paths
        left = ttk.Labelframe(pane, text=" Monitored paths ", padding=8)
        self.paths_list = tk.Listbox(left, activestyle="dotbox", height=16)
        self.paths_list.pack(fill="both", expand=True)
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Add folder…", command=self._add_folder).pack(
            side="left", padx=2)
        ttk.Button(btns, text="Add file…", command=self._add_file).pack(
            side="left", padx=2)
        ttk.Button(btns, text="Remove", command=self._remove_path).pack(
            side="left", padx=2)
        pane.add(left, weight=1)

        # Right: controls + results
        right = ttk.Frame(pane)
        pane.add(right, weight=3)

        ctrl = ttk.Labelframe(right, text=" Operations ", padding=8)
        ctrl.pack(fill="x")
        self.mode_var = tk.StringVar(value="quick")
        ttk.Radiobutton(ctrl, text="Quick scan (size+mtime, rehash changed)",
                        variable=self.mode_var, value="quick").pack(anchor="w")
        ttk.Radiobutton(ctrl, text="Full scan (rehash every file — slower)",
                        variable=self.mode_var, value="full").pack(anchor="w")
        row = ttk.Frame(ctrl)
        row.pack(fill="x", pady=(6, 0))
        self.btn_baseline = ttk.Button(row, text="Build / Rebuild Baseline",
                                       command=self._build_baseline)
        self.btn_baseline.pack(side="left", padx=2)
        self.btn_verify = ttk.Button(row, text="Verify Now",
                                     command=self._verify_now)
        self.btn_verify.pack(side="left", padx=2)
        self.progress = ttk.Progressbar(ctrl, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(8, 0))

        self.baseline_info = tk.StringVar(value="Baseline: —")
        ttk.Label(right, textvariable=self.baseline_info).pack(anchor="w", pady=6)

        results = ttk.Labelframe(right, text=" Last verification results ", padding=4)
        results.pack(fill="both", expand=True)
        frame, self.tree = make_tree(results, [
            ("time", "Time", 130, "w"),
            ("change", "Change", 90, "center"),
            ("path", "Path", 430, "w"),
            ("detail", "Detail", 260, "w"),
        ], height=14)
        frame.pack(fill="both", expand=True)
        self.tree.tag_configure("ADDED", foreground="#2e7d32")
        self.tree.tag_configure("MODIFIED", foreground=SEV_COLORS["MEDIUM"])
        self.tree.tag_configure("DELETED", foreground=SEV_COLORS["CRITICAL"])

    # -- actions ------------------------------------------------------------
    def reload_paths(self):
        self.paths_list.delete(0, "end")
        for p in self.app.config.get("monitored_paths") or []:
            self.paths_list.insert("end", p)

    def _save_paths(self, paths):
        self.app.config.set("monitored_paths", paths)
        self.app.config.save()
        if self.app.monitoring:
            self.app.log_line("Monitored paths changed — restart monitoring to "
                              "watch new paths in real time")

    def _add_folder(self):
        d = filedialog.askdirectory(title="Choose folder to monitor")
        if not d:
            return
        paths = list(self.app.config.get("monitored_paths") or [])
        if d not in paths:
            paths.append(d)
            self._save_paths(paths)
            self.reload_paths()

    def _add_file(self):
        f = filedialog.askopenfilename(title="Choose file to monitor")
        if not f:
            return
        paths = list(self.app.config.get("monitored_paths") or [])
        if f not in paths:
            paths.append(f)
            self._save_paths(paths)
            self.reload_paths()

    def _remove_path(self):
        sel = self.paths_list.curselection()
        if not sel:
            return
        paths = list(self.app.config.get("monitored_paths") or [])
        removed = paths.pop(sel[0])
        self._save_paths(paths)
        self.reload_paths()
        self.app.log_line(f"Removed monitored path: {removed}")

    def _build_baseline(self):
        paths = self.app.config.get("monitored_paths") or []
        if not paths:
            messagebox.showwarning("No paths", "Add at least one monitored path first.")
            return
        if self._busy:
            return
        if self.app.db.baseline_count() > 0 and not messagebox.askyesno(
                "Rebuild baseline",
                "Rebuilding replaces the existing baseline.\nContinue?"):
            return
        self._set_busy(True, self.btn_baseline)

        def work():
            try:
                result = self.app.fim.build_baseline()
                self.app.ui_call(self._after_baseline, result)
            except Exception as exc:
                self.app.ui_call(self._worker_error, "Baseline build failed", exc)

        threading.Thread(target=work, daemon=True).start()

    def _after_baseline(self, result):
        self._set_busy(False, self.btn_baseline)
        self.progress["value"] = 0
        self.refresh_baseline_info()
        self.app.log_line(f"Baseline built: {result['files']} files, "
                          f"{result['errors']} errors")
        messagebox.showinfo("Baseline built",
                            f"Baselined {result['files']} files "
                            f"({result['errors']} skipped/errors).")

    def _verify_now(self):
        if self._busy:
            return
        if self.app.db.baseline_count() == 0:
            messagebox.showwarning("No baseline", "Build a baseline first.")
            return
        self._set_busy(True, self.btn_verify)
        full = self.mode_var.get() == "full"

        def work():
            try:
                changes = self.app.fim.verify(full=full)
                self.app.ui_call(self._after_verify, changes)
            except Exception as exc:
                self.app.ui_call(self._worker_error, "Verification failed", exc)

        threading.Thread(target=work, daemon=True).start()

    def _after_verify(self, changes):
        self._set_busy(False, self.btn_verify)
        self.tree.delete(*self.tree.get_children())
        finished_ts = 0.0
        row = self.app.db.last_scan()
        if row is not None and row["finished"]:
            finished_ts = row["finished"]
        stamp = ts_str(finished_ts) if finished_ts else ts_str(time.time())
        for c in reversed(changes):
            detail = ""
            if c.change == "MODIFIED" and c.old and c.new:
                detail = (f"{human_size(c.old.size)}→{human_size(c.new.size)} "
                          f"sha {c.old.sha256[:12]}→{c.new.sha256[:12]}")
            elif c.change == "ADDED" and c.new:
                detail = f"{human_size(c.new.size)} sha {c.new.sha256[:12]}"
            elif c.change == "DELETED" and c.old:
                detail = f"was {human_size(c.old.size)} sha {c.old.sha256[:12]}"
            self.tree.insert("", 0, values=(
                stamp, c.change, c.path, detail), tags=(c.change,))
        self.refresh_baseline_info()

    def _worker_error(self, title, exc):
        self._set_busy(False, self.btn_baseline, self.btn_verify)
        self.app.log_line(f"{title}: {exc}")
        messagebox.showerror(title, str(exc))

    # -- events from app -----------------------------------------------------
    def on_progress(self, payload):
        done, total = payload.get("done", 0), max(payload.get("total", 1), 1)
        self.progress["value"] = min(100.0, done * 100.0 / total)

    def on_scan_finished(self, payload):
        stats = payload.get("stats", {})
        self.progress["value"] = 0
        self.tree.delete(*self.tree.get_children())
        for c in reversed(payload.get("changes") or []):
            self.tree.insert("", 0, values=(
                ts_str(stats.get("finished_ts", 0)), c.change, c.path, ""), tags=(c.change,))
        self.refresh_baseline_info()

    def refresh_baseline_info(self):
        count = self.app.db.baseline_count()
        built = self.app.db.get_meta("baseline_built")
        built_s = ts_str(float(built)) if built else "—"
        rt = "ON" if getattr(self.app.fim, "realtime_active", False) else "off"
        self.baseline_info.set(
            f"Baseline: {count} files | built: {built_s} | last scan: "
            f"{self.app.fim.last_scan_str()} | real-time: {rt}")

    def _set_busy(self, busy, *buttons):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in buttons:
            b["state"] = state
