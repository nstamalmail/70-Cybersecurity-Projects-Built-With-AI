"""Settings tab: engine tuning, exclusions, retention, data folder."""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk


class SettingsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        self._build()
        self._load_values()

    def _build(self):
        tuning = ttk.Labelframe(self, text=" Engine tuning ", padding=10)
        tuning.pack(fill="x")
        self.vars = {}
        fields = [
            ("scan_interval_seconds", "FIM sweep interval (seconds) — safety net", 8),
            ("realtime_debounce_seconds", "Real-time debounce (seconds of quiet)", 8),
            ("process_poll_seconds", "Process poll interval (seconds)", 8),
            ("max_file_size_mb", "Max hashed file size (MB)", 8),
            ("burst_threshold", "Burst alert threshold (files)", 8),
            ("burst_window_seconds", "Burst window (seconds)", 8),
            ("burst_cooldown_seconds", "Burst alert cooldown (seconds)", 8),
            ("alert_retention_days", "Alert retention (days)", 8),
            ("process_alert_cooldown_seconds", "Rule alert cooldown per process (seconds)", 8),
        ]
        for i, (key, label, width) in enumerate(fields):
            ttk.Label(tuning, text=label).grid(row=i, column=0, sticky="w", pady=2)
            var = tk.StringVar()
            ttk.Entry(tuning, textvariable=var, width=width).grid(
                row=i, column=1, sticky="w", padx=8, pady=2)
            self.vars[key] = var

        self.realtime_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(tuning, text="Real-time FIM — instant alerts on file changes (watchdog)",
                        variable=self.realtime_enabled).grid(
            row=len(fields), column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.alert_on_new = tk.BooleanVar(value=False)
        ttk.Checkbutton(tuning, text="Raise INFO alert for every new process (noisy)",
                        variable=self.alert_on_new).grid(
            row=len(fields) + 1, column=0, columnspan=2, sticky="w")

        ttk.Button(tuning, text="Save Settings",
                   command=self._save).grid(row=len(fields) + 2, column=0,
                                            columnspan=2, sticky="w", pady=10)

        excl = ttk.Labelframe(self, text=" Exclusion patterns ", padding=10)
        excl.pack(fill="both", expand=True, pady=(10, 0))
        body = ttk.Frame(excl)
        body.pack(fill="both", expand=True)
        self.excl_list = tk.Listbox(body, height=8)
        self.excl_list.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(body, command=self.excl_list.yview)
        sb.pack(side="left", fill="y")
        self.excl_list.configure(yscrollcommand=sb.set)
        btns = ttk.Frame(excl)
        btns.pack(side="left", padx=8, anchor="n")
        ttk.Button(btns, text="Add", command=self._add_excl).pack(fill="x", pady=2)
        ttk.Button(btns, text="Remove", command=self._del_excl).pack(fill="x", pady=2)

        storage = ttk.Labelframe(self, text=" Storage ", padding=10)
        storage.pack(fill="x", pady=(10, 0))
        self.data_label = ttk.Label(storage, text="")
        self.data_label.pack(anchor="w")
        ttk.Button(storage, text="Open data folder",
                   command=self._open_data).pack(anchor="w", pady=4)

    # -- data -----------------------------------------------------------------
    def _load_values(self):
        cfg = self.app.config
        for key, var in self.vars.items():
            var.set(str(cfg.get(key, "")))
        self.realtime_enabled.set(bool(cfg.get("realtime_fim", True)))
        self.alert_on_new.set(bool((cfg.get("process_rules") or {}).get("alert_on_new_process")))
        self.excl_list.delete(0, "end")
        for p in cfg.get("exclude_patterns") or []:
            self.excl_list.insert("end", p)
        self.data_label["text"] = f"Data directory: {self.app.data_dir}"

    def _save(self):
        cfg = self.app.config
        for key, var in self.vars.items():
            raw = var.get().strip()
            try:
                value = int(raw)
                if value < 1:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid value",
                                     f"'{key}' must be a positive integer.")
                return
            cfg.set(key, value)
        cfg.set("realtime_fim", self.realtime_enabled.get())
        cfg.set("process_rules", {"alert_on_new_process": self.alert_on_new.get()})
        cfg.save()
        self._load_values()
        self.app.log_line("Settings saved. Real-time toggle applies after restarting monitoring; "
                          "intervals apply on the next engine cycle.")
        messagebox.showinfo("Saved", "Settings saved.")

    def _add_excl(self):
        win = tk.Toplevel(self)
        win.title("Add exclusion pattern")
        win.geometry("460x120")
        ttk.Label(win, text="Pattern (fnmatch, e.g. *.log or C:/Windows/Temp/)").pack(
            anchor="w", padx=10, pady=(10, 4))
        var = tk.StringVar()
        ent = ttk.Entry(win, textvariable=var)
        ent.pack(fill="x", padx=10)
        ent.focus_set()

        def done():
            pat = var.get().strip()
            if pat:
                pats = list(self.app.config.get("exclude_patterns") or [])
                if pat not in pats:
                    pats.append(pat)
                    self.app.config.set("exclude_patterns", pats)
                    self.app.config.save()
                    self._load_values()
            win.destroy()

        ttk.Button(win, text="Add", command=done).pack(anchor="e", padx=10, pady=8)
        win.bind("<Return>", lambda e: done())

    def _del_excl(self):
        sel = self.excl_list.curselection()
        if not sel:
            return
        pats = list(self.app.config.get("exclude_patterns") or [])
        del pats[sel[0]]
        self.app.config.set("exclude_patterns", pats)
        self.app.config.save()
        self._load_values()

    def _open_data(self):
        path = str(self.app.data_dir)
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except OSError as exc:
            messagebox.showerror("Open folder", str(exc))
