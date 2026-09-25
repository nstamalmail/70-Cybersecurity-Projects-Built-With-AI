"""SIDT GUI tabs: Target, Parameters, Scan, Findings, Reports, Settings."""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_data_dir
from app.gui.widgets import (ACCENT, FONT_FAMILY, make_tree, add_text,
                             log_to_text)

TECHNIQUE_LABELS = [("error", "Error-based"), ("boolean", "Boolean-based blind"),
                    ("time", "Time-based blind"), ("union", "Union-based")]


class TargetTab(ttk.Frame):
    """URL, method, headers, cookies, body + demo target loader."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(1, weight=1)
        self.rowconfigure(5, weight=1)
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)

        ttk.Label(self, text="Target URL:").grid(row=0, column=0, sticky="w", **pad)
        self.url_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.url_var).grid(
            row=0, column=1, sticky="ew", **pad)

        ttk.Label(self, text="Method:").grid(row=1, column=0, sticky="w", **pad)
        self.method_var = tk.StringVar(value="GET")
        ttk.Combobox(self, textvariable=self.method_var, state="readonly",
                     values=["GET", "POST", "PUT", "PATCH", "DELETE"],
                     width=12).grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(self, text="Headers (Key: Value per line):").grid(
            row=2, column=0, sticky="nw", **pad)
        wrap_h = ttk.Frame(self, style="TFrame")
        wrap_h.grid(row=2, column=1, sticky="ew", **pad)
        self.headers_text = add_text(wrap_h, height=4)


        ttk.Label(self, text="Cookies (k=v; k2=v2):").grid(row=3, column=0, sticky="nw", **pad)
        wrap_c = ttk.Frame(self, style="TFrame")
        wrap_c.grid(row=3, column=1, sticky="ew", **pad)
        self.cookies_text = add_text(wrap_c, height=2)


        bodyf = ttk.Frame(self, style="TFrame")
        bodyf.grid(row=4, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Label(bodyf, text="Body:").pack(side="left")
        self.body_type_var = tk.StringVar(value="none")
        ttk.Combobox(bodyf, textvariable=self.body_type_var, state="readonly",
                     values=["none", "form", "json", "raw"], width=8).pack(side="left", padx=6)
        self.body_text = add_text(bodyf, height=4)
        self.body_text.pack(fill="both", expand=True, padx=6)

        row = ttk.Frame(self, style="TFrame")
        row.grid(row=5, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Button(row, text="✨ Load demo target URL",
                   command=self._load_demo).pack(side="left")
        ttk.Button(row, text="⬆ Import parameters JSON…",
                   command=self._import_params).pack(side="left", padx=6)

        hint = ("Demo target: run `python samples/demo_target.py`, then use "
                "http://127.0.0.1:8765/search?user=admin — or import "
                "samples/sample_parameters.json for manual parameter entry.")
        ttk.Label(self, text=hint, foreground="#7f849c",
                  wraplength=980, justify="left").grid(
            row=6, column=0, columnspan=2, sticky="w", **pad)

    def _load_demo(self):
        self.url_var.set("http://127.0.0.1:8765/search?user=admin")
        self.method_var.set("GET")
        self.headers_text.delete("1.0", "end")
        self.headers_text.insert("1.0", "Accept: text/html")
        self.cookies_text.delete("1.0", "end")
        self.cookies_text.insert("1.0", "session=demo-session-42")

    def _import_params(self):
        path = filedialog.askopenfilename(
            title="Import parameters JSON", initialdir=SAMPLES_DIR,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        cb = getattr(self, "on_import_parameters", None)
        if cb:
            cb(path)

    # ---------------------------------------------------------- data mapping
    def collect(self):
        return {
            "target_url": self.url_var.get().strip(),
            "method": self.method_var.get(),
            "headers_text": self.headers_text.get("1.0", "end").strip(),
            "cookies_text": self.cookies_text.get("1.0", "end").strip(),
            "body": self.body_text.get("1.0", "end").strip(),
            "body_type": self.body_type_var.get(),
        }

    def apply(self, data: dict):
        self.url_var.set(data.get("target_url", data.get("url", "")))
        self.method_var.set(data.get("method", "GET"))
        self.headers_text.delete("1.0", "end")
        headers = data.get("headers", {})
        if isinstance(headers, str):
            self.headers_text.insert("1.0", headers)
        else:
            self.headers_text.insert("1.0",
                                     "\n".join(f"{k}: {v}" for k, v in headers.items()))
        self.cookies_text.delete("1.0", "end")
        cookies = data.get("cookies", {})
        if isinstance(cookies, str):
            self.cookies_text.insert("1.0", cookies)
        else:
            self.cookies_text.insert("1.0",
                                     "; ".join(f"{k}={v}" for k, v in cookies.items()))
        self.body_text.delete("1.0", "end")
        self.body_text.insert("1.0", data.get("body", ""))
        self.body_type_var.set(data.get("body_type", "none"))


class ParametersTab(ttk.Frame):
    """Parameter inventory with enable/disable + manual JSON import."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        tree_wrap = ttk.Frame(self, style="TFrame")
        tree_wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 0))
        self.tree = make_tree(
            tree_wrap, ("sel", "location", "name", "value"),
            ("", "Location", "Name", "Sample value"),
            (40, 90, 180, 480), selectmode="extended")
        self.tree.heading("sel", text="")
        self.tree.column("sel", width=40, stretch=False)

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=6)
        ttk.Button(btns, text="⬆ Import parameters JSON…",
                   command=self._import).pack(side="left")
        ttk.Button(btns, text="＋ Add parameter…",
                   command=self._add_manual).pack(side="left", padx=6)
        ttk.Button(btns, text="✎ Toggle enabled",
                   command=self._toggle).pack(side="left", padx=6)
        ttk.Button(btns, text="✖ Remove selected",
                   command=self._remove).pack(side="left", padx=6)

    def set_parameters(self, params: list):
        self.tree.delete(*self.tree.get_children())
        for i, p in enumerate(params):
            self.tree.insert("", "end", iid=str(i), values=(
                "✔" if p.get("enabled", True) else "—",
                p.get("location", "query"), p.get("name", ""),
                p.get("value", "")[:80]))

    def get_all(self) -> list:
        out = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            out.append({"enabled": vals[0] == "✔", "location": vals[1],
                        "name": vals[2], "value": vals[3]})
        return out

    def get_enabled(self) -> list:
        return [p for p in self.get_all() if p["enabled"]]

    def _import(self):
        path = filedialog.askopenfilename(
            title="Import parameters JSON", initialdir=SAMPLES_DIR,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        cb = getattr(self, "on_import_parameters", None)
        if cb:
            cb(path)

    def _add_manual(self):
        dlg = _ManualParamDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            items = self.get_all()
            items.append(dlg.result)
            self.set_parameters(items)

    def _toggle(self):
        for iid in self.tree.selection():
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "—" if vals[0] == "✔" else "✔"
            self.tree.item(iid, values=vals)

    def _remove(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)


class _ManualParamDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Add parameter")
        self.result = None
        self.transient(master.winfo_toplevel())
        self.grab_set()
        frm = ttk.Frame(self, padding=10, style="TFrame")
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Location:").grid(row=0, column=0, sticky="w")
        self.loc = tk.StringVar(value="query")
        ttk.Combobox(frm, textvariable=self.loc, state="readonly",
                     values=["query", "body", "header", "cookie"],
                     width=14).grid(row=0, column=1, sticky="ew", padx=6, pady=3)
        ttk.Label(frm, text="Name:").grid(row=1, column=0, sticky="w")
        self.name = tk.StringVar()
        ttk.Entry(frm, textvariable=self.name, width=24).grid(
            row=1, column=1, sticky="ew", padx=6, pady=3)
        ttk.Label(frm, text="Sample value:").grid(row=2, column=0, sticky="w")
        self.val = tk.StringVar()
        ttk.Entry(frm, textvariable=self.val, width=24).grid(
            row=2, column=1, sticky="ew", padx=6, pady=3)
        btns = ttk.Frame(frm, style="TFrame")
        btns.grid(row=3, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        ttk.Button(btns, text="Add", style="Accent.TButton",
                   command=self._ok).pack(side="left")

    def _ok(self):
        if not self.name.get().strip():
            messagebox.showwarning(APP_NAME, "Parameter name required.")
            return
        self.result = {"location": self.loc.get(), "name": self.name.get().strip(),
                       "value": self.val.get(), "enabled": True}
        self.destroy()


class ScanTab(ttk.Frame):
    """Technique selection (safe mode), run controls, live console, stats."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)
        self._build()
        self.set_running(False)

    def _build(self):
        pad = dict(padx=10, pady=4)
        top = ttk.Frame(self, style="TFrame")
        top.grid(row=0, column=0, sticky="ew", **pad)

        self.safe_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Safe mode (error + boolean only; no time/union)",
                        variable=self.safe_var,
                        command=self._safe_changed).pack(side="left")

        tech = ttk.LabelFrame(self, text=" Techniques ", padding=8)
        tech.grid(row=1, column=0, sticky="ew", **pad)
        self.tech_vars = {}
        for key, label in TECHNIQUE_LABELS:
            var = tk.BooleanVar(value=key in ("error", "boolean"))
            self.tech_vars[key] = var
            cb = ttk.Checkbutton(tech, text=label, variable=var,
                                 command=self._safe_changed)
            cb.pack(side="left", padx=(0, 14))

        opts = ttk.LabelFrame(self, text=" Options ", padding=8)
        opts.grid(row=2, column=0, sticky="ew", **pad)
        ttk.Label(opts, text="Delay (ms):").pack(side="left")
        self.delay_var = tk.IntVar(value=40)
        ttk.Spinbox(opts, from_=0, to=5000, textvariable=self.delay_var,
                    width=7).pack(side="left", padx=(4, 12))
        ttk.Label(opts, text="Timeout (s):").pack(side="left")
        self.timeout_var = tk.DoubleVar(value=10.0)
        ttk.Spinbox(opts, from_=1, to=120, increment=0.5,
                    textvariable=self.timeout_var, width=6).pack(side="left", padx=(4, 12))
        ttk.Label(opts, text="Time threshold (s):").pack(side="left")
        self.time_thr_var = tk.DoubleVar(value=5.0)
        ttk.Spinbox(opts, from_=1, to=10, increment=0.5,
                    textvariable=self.time_thr_var, width=6).pack(side="left", padx=(4, 12))
        ttk.Label(opts, text="Proxy:").pack(side="left")
        self.proxy_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.proxy_var, width=22).pack(
            side="left", padx=(4, 12))
        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Verify TLS", variable=self.verify_var).pack(side="left")

        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text=("I confirm I own this target or have written "
                                    "authorization to test it."),
                        variable=self.auth_var).grid(row=3, column=0, sticky="w", **pad)

        ctrl = ttk.Frame(self, style="TFrame")
        ctrl.grid(row=4, column=0, sticky="ew", **pad)
        self.start_btn = ttk.Button(ctrl, text="▶ Start scan", style="Accent.TButton",
                                    command=self._start)
        self.start_btn.pack(side="left")
        self.pause_btn = ttk.Button(ctrl, text="⏸ Pause", command=self._pause)
        self.pause_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(ctrl, text="⏹ Stop", style="Danger.TButton",
                                   command=self._stop)
        self.stop_btn.pack(side="left", padx=6)
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(ctrl, textvariable=self.status_var, foreground=ACCENT).pack(
            side="left", padx=14)
        self.progress = ttk.Progressbar(ctrl, length=320, mode="determinate")
        self.progress.pack(side="right")

        stats = ttk.Frame(self, style="TFrame")
        stats.grid(row=5, column=0, sticky="ew", **pad)
        self.stat_vars = {k: tk.StringVar(value="0") for k in
                          ("requests", "errors", "findings", "parameters")}
        for label, key in (("Requests", "requests"), ("Errors", "errors"),
                           ("Findings", "findings"), ("Parameters", "parameters")):
            box = ttk.Frame(stats, style="Card.TFrame", padding=(14, 6))
            box.pack(side="left", padx=(0, 8))
            ttk.Label(box, text=label, foreground="#7f849c",
                      font=(FONT_FAMILY, 8)).pack(anchor="w")
            ttk.Label(box, textvariable=self.stat_vars[key],
                      font=(FONT_FAMILY, 13, "bold")).pack(anchor="w")

        con = ttk.LabelFrame(self, text=" Console ", padding=4)
        con.grid(row=6, column=0, sticky="nsew", **pad)
        self.log_text = add_text(con, height=12)
        self.log_text.tag_configure("warn", foreground="#f9e2af")

    def _safe_changed(self):
        if self.safe_var.get():
            self.tech_vars["time"].set(False)
            self.tech_vars["union"].set(False)

    def _start(self):
        cb = getattr(self, "on_scan", None)
        if cb:
            cb()

    def _pause(self):
        cb = getattr(self, "on_pause", None)
        if cb:
            cb()

    def _stop(self):
        cb = getattr(self, "on_stop", None)
        if cb:
            cb()

    def collect(self) -> dict:
        return {
            "safe_mode": self.safe_var.get(),
            "techniques": [k for k, v in self.tech_vars.items() if v.get()],
            "delay_ms": int(self.delay_var.get() or 0),
            "timeout": float(self.timeout_var.get() or 10.0),
            "time_threshold_s": float(self.time_thr_var.get() or 5.0),
            "proxy": self.proxy_var.get().strip(),
            "verify_ssl": self.verify_var.get(),
            "authorized": self.auth_var.get(),
        }

    def apply(self, data: dict):
        self.safe_var.set(data.get("safe_mode", True))
        techs = data.get("techniques", ["error", "boolean"])
        for k, v in self.tech_vars.items():
            v.set(k in techs)
        self.delay_var.set(int(data.get("delay_ms", 40) or 0))
        self.timeout_var.set(float(data.get("timeout", 10.0) or 10.0))
        self.time_thr_var.set(float(data.get("time_threshold_s", 5.0) or 5.0))
        self.proxy_var.set(data.get("proxy", "") or "")
        self.verify_var.set(bool(data.get("verify_ssl", True)))

    def set_running(self, running: bool):
        state = "disabled" if running else "normal"
        self.start_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if running else "disabled")
        self.pause_btn.configure(state="normal" if running else "disabled")

    def set_status(self, text: str):
        self.status_var.set(text)

    def set_progress(self, done: int, total: int):
        self.progress.configure(maximum=max(total, 1), value=done)

    def set_stats(self, requests: int, errors: int, findings: int,
                  parameters: int = 0):
        self.stat_vars["requests"].set(str(requests))
        self.stat_vars["errors"].set(str(errors))
        self.stat_vars["findings"].set(str(findings))
        if parameters:
            self.stat_vars["parameters"].set(str(parameters))

    def log(self, line: str, tag: str = ""):
        log_to_text(self.log_text, line, tag)

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")


class FindingsTab(ttk.Frame):
    """Findings table + evidence/inspector detail pane."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.rowconfigure(0, weight=3)
        self.rowconfigure(1, weight=2)
        self.columnconfigure(0, weight=1)
        self._findings: list = []
        self._build()

    def _build(self):
        tree_wrap = ttk.Frame(self, style="TFrame")
        tree_wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.tree = make_tree(
            tree_wrap, ("sev", "location", "param", "technique", "confidence", "dbms", "signal"),
            ("Severity", "Location", "Parameter", "Technique", "Confidence", "DBMS", "Signal"),
            (80, 80, 140, 100, 90, 90, 420))
        self.tree.tag_configure("critical", foreground="#f38ba8")
        self.tree.tag_configure("high", foreground="#f38ba8")
        self.tree.tag_configure("medium", foreground="#f9e2af")
        self.tree.tag_configure("low", foreground="#a6e3a1")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        self.tree.bind("<Double-1>", lambda e: self._show_detail())

        nb = ttk.Notebook(self)
        nb.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.detail_evidence = add_text(nb, height=10)
        self.detail_remediation = add_text(nb, height=10)
        nb.add(self.detail_evidence, text=" Evidence ")
        nb.add(self.detail_remediation, text=" Remediation ")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self._findings = []

    def add_finding(self, f: dict):
        self._findings.append(f)
        self.tree.insert("", "end", values=(
            f.get("severity", "").upper(), f.get("parameter_location", ""),
            f.get("parameter_name", ""), f"{f.get('technique', '')}-based",
            f.get("confidence", ""), f.get("dbms_hint", "") or "—",
            (f.get("signal", "") or "")[:120]),
            tags=(f.get("severity", "info"),))

    def set_findings(self, findings: list):
        self.clear()
        for f in findings:
            self.add_finding(f)

    def _show_detail(self, *_):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self._findings):
            return
        f = self._findings[idx]
        delta = f.get("response_delta") or {}
        if not isinstance(delta, dict):
            delta = {}
        text = (
            f"URL: {f.get('url', '')}\n"
            f"Method: {f.get('method', '')}\n"
            f"Parameter: {f.get('parameter_location', '')}:{f.get('parameter_name', '')}\n"
            f"Technique: {f.get('technique', '')}  Confidence: {f.get('confidence', '')}\n"
            f"DBMS hint: {f.get('dbms_hint', '') or 'n/a'}\n"
            f"Payload: {f.get('payload', '')}\n"
            f"Signal: {f.get('signal', '')}\n"
            f"Response delta: {json.dumps(delta, default=str)}\n"
            f"{'-' * 70}\nBASELINE REQUEST\n{f.get('baseline_request', '')}\n"
            f"{'-' * 70}\nINJECTED REQUEST\n{f.get('injected_request', '')}\n"
            f"{'-' * 70}\nBASELINE RESPONSE\n{f.get('baseline_response_snippet', '')}\n"
            f"{'-' * 70}\nINJECTED RESPONSE\n{f.get('injected_response_snippet', '')}\n"
        )
        for widget in (self.detail_evidence,):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")
        rem = f.get("remediation", "") or ""
        self.detail_remediation.configure(state="normal")
        self.detail_remediation.delete("1.0", "end")
        self.detail_remediation.insert("1.0", rem)
        self.detail_remediation.configure(state="disabled")


class ReportsTab(ttk.Frame):
    """Scan history, findings-file import, and multi-format export."""

    def __init__(self, master, db=None):
        super().__init__(master, style="TFrame")
        self.db = db
        self.on_load_findings = None
        self.on_imported_scan = None
        self.on_memory_log = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)
        self._build()

    def _build(self):
        card = ttk.LabelFrame(self, text=" Scan history (SQLite) ", padding=6)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))
        self.scans_tree = make_tree(
            card, ("id", "started", "finished", "target", "params", "requests",
                   "findings", "errors"),
            ("ID", "Started", "Finished", "Target", "Params", "Requests",
             "Findings", "Errors"),
            (44, 130, 130, 300, 70, 90, 84, 70))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btns, text="↻ Refresh", command=self.refresh).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="📄 Load into Findings tab",
                   command=self._load_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="⬆ Import findings file…", style="Accent.TButton",
                   command=self._import_findings_file).pack(side="left", padx=6)
        ttk.Button(btns, text="💾 Export HTML/CSV/JSON…", style="Accent.TButton",
                   command=self._export_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Delete selected", style="Danger.TButton",
                   command=self._delete_selected).pack(side="left", padx=6)

    def refresh(self):
        if not self.db:
            return
        self.scans_tree.delete(*self.scans_tree.get_children())
        for row in self.db.list_scans():
            self.scans_tree.insert("", "end", values=(
                row["id"], row["started_at"], row["finished_at"] or "",
                row["target"], row["parameters_tested"], row["total_requests"],
                row["findings_count"], row["errors"]))

    def _selected_scan_id(self):
        sel = self.scans_tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a scan first.")
            return None
        return int(self.scans_tree.item(sel[0], "values")[0])

    def _load_selected(self):
        sid = self._selected_scan_id()
        if sid is None or not self.db:
            return
        findings = self.db.list_findings(sid)
        if self.on_load_findings:
            self.on_load_findings(sid, findings)

    def _import_findings_file(self):
        """Import findings from JSON to generate a report without a live scan."""
        from app.core.report_import import parse_findings_doc
        from app.core.models import SqlInjectionFinding
        from app.core.remediation import build_remediation

        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Import findings file (JSON)", initialdir=initial,
            filetypes=[("JSON findings", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read JSON: {exc}")
            return
        findings_raw, scan_meta = parse_findings_doc(doc)
        if not findings_raw:
            messagebox.showwarning(APP_NAME, "No usable findings found in file.")
            return
        if not self.db:
            messagebox.showerror(APP_NAME, "Database not available.")
            return
        scan_id = self.db.create_scan({"to_dict": lambda: scan_meta},
                                      scan_meta.get("target", "imported"),
                                      safe_mode=scan_meta.get("safe_mode", True))
        for item in findings_raw:
            f = SqlInjectionFinding(
                url=item.get("url", ""), method=item.get("method", "GET"),
                parameter_name=item.get("parameter_name", ""),
                parameter_location=item.get("parameter_location", "query"),
                technique=item.get("technique", "error"),
                confidence=item.get("confidence", "medium"),
                severity=item.get("severity", "medium"),
                dbms_hint=item.get("dbms_hint", ""),
                signal=item.get("signal", ""),
                payload=item.get("payload", ""),
                baseline_request=item.get("baseline_request", ""),
                injected_request=item.get("injected_request", ""),
                baseline_response_snippet=item.get("baseline_response_snippet", ""),
                injected_response_snippet=item.get("injected_response_snippet", ""),
                response_delta=item.get("response_delta") or {},
                remediation=item.get("remediation")
                or build_remediation(item.get("technique", "error"),
                                     item.get("dbms_hint", "")),
                references=item.get("references", []),
                status=int(item.get("status", 0) or 0),
                resp_time_ms=float(item.get("resp_time_ms", 0) or 0.0),
            )
            self.db.insert_finding(scan_id, f)
        self.db.finish_scan(scan_id, scan_meta.get("parameters_tested", len(findings_raw)),
                            scan_meta.get("total_requests", 0), len(findings_raw),
                            scan_meta.get("errors", 0), scan_meta.get("waf", ""))
        self.refresh()
        if self.on_imported_scan:
            self.on_imported_scan(scan_id, self.db.list_findings(scan_id))
        self._maybe_export(scan_id, scan_meta, len(findings_raw), source=path)

    def _maybe_export(self, scan_id: int, scan_meta: dict, count: int,
                      source: str = ""):
        if not messagebox.askyesno(
                APP_NAME,
                f"Imported {count} finding(s) as scan #{scan_id}"
                + (f" from\n{source}" if source else "")
                + "\n\nGenerate the HTML/CSV/JSON report now?"):
            return
        self._export_scan(scan_id)

    def _export_selected(self):
        sid = self._selected_scan_id()
        if sid is None:
            return
        self._export_scan(sid)

    def _export_scan(self, scan_id: int):
        from app.core.report import export_all
        scan = self.db.get_scan(scan_id)
        if not scan:
            return
        findings = self.db.list_findings(scan_id)
        directory = filedialog.askdirectory(title="Choose export folder")
        if not directory:
            return
        try:
            paths = export_all(scan, findings, directory,
                               started=scan.get("started_at", ""),
                               finished=scan.get("finished_at", ""))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        messagebox.showinfo(APP_NAME,
                            "Report exported (downloaded):\n" +
                            "\n".join(f"• {p}" for p in paths.values()))
        if self.on_memory_log:
            self.on_memory_log(f"report exported for scan #{scan_id}")

    def _delete_selected(self):
        sid = self._selected_scan_id()
        if sid is None:
            return
        if messagebox.askyesno(APP_NAME, f"Delete scan #{sid} and its findings?"):
            self.db.delete_scan(sid)
            self.refresh()


class SettingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self._build()

    def _build(self):
        card = ttk.LabelFrame(self, text=" Portable paths ", padding=10)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.paths_text = add_text(card, height=10)
        self.paths_text.insert("1.0", "starting…")

        mem = ttk.LabelFrame(self, text=" Recent memory (memory.md) ", padding=10)
        mem.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.memory_text = add_text(mem, height=12)

    def set_paths(self, mapping: dict):
        self.paths_text.configure(state="normal")
        self.paths_text.delete("1.0", "end")
        self.paths_text.insert("1.0", "\n".join(f"{k}: {v}" for k, v in mapping.items()))
        self.paths_text.configure(state="disabled")

    def refresh_memory(self, lines: list):
        self.memory_text.configure(state="normal")
        self.memory_text.delete("1.0", "end")
        self.memory_text.insert("1.0", "\n".join(lines) or "(empty)")
        self.memory_text.configure(state="disabled")
