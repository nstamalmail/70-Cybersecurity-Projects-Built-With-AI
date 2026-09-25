"""CBSEF GUI tabs: Config, Live findings, Inspector, Reports, Bridge, Settings."""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_data_dir
from app.gui.widgets import (ACCENT, FONT_FAMILY, add_text, log_to_text,
                             make_tree)

TEST_CASE_LABELS = [("mass_assignment", "Mass assignment"),
                    ("jwt_confusion", "JWT algorithm confusion"),
                    ("oauth_redirect", "OAuth redirect_uri"),
                    ("introspection", "GraphQL introspection")]


class ConfigTab(ttk.Frame):
    """Bridge settings + test-case selection."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.on_start_bridge = None
        self.on_stop_bridge = None
        self.columnconfigure(1, weight=1)
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        bf = ttk.LabelFrame(self, text=" Loopback bridge (extension → GUI) ",
                            padding=8)
        bf.grid(row=0, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Label(bf, text="Port:").pack(side="left")
        self.port_var = tk.IntVar(value=8737)
        ttk.Spinbox(bf, from_=1024, to=65535, textvariable=self.port_var,
                    width=7).pack(side="left", padx=(4, 14))
        ttk.Label(bf, text="Token (optional):").pack(side="left")
        self.token_var = tk.StringVar()
        ttk.Entry(bf, textvariable=self.token_var, width=24,
                  show="•").pack(side="left", padx=(4, 14))
        self.start_btn = ttk.Button(bf, text="▶ Start bridge", style="Accent.TButton",
                                    command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bf, text="⏹ Stop", style="Danger.TButton",
                                   command=self._stop)
        self.stop_btn.pack(side="left", padx=6)
        self.bridge_status_var = tk.StringVar(value="stopped")
        ttk.Label(bf, textvariable=self.bridge_status_var,
                  foreground=ACCENT).pack(side="left", padx=10)

        tf = ttk.LabelFrame(self, text=" Test cases (analyzers run on "
                                       "submitted/pasted traffic) ", padding=8)
        tf.grid(row=1, column=0, columnspan=2, sticky="ew", **pad)
        self.tc_vars = {}
        for key, label in TEST_CASE_LABELS:
            var = tk.BooleanVar(value=key == "mass_assignment")
            self.tc_vars[key] = var
            ttk.Checkbutton(tf, text=label, variable=var).pack(side="left",
                                                               padx=(0, 14))

        hint = (
            "Companion GUI workflow:\n"
            "  1. Start the bridge; the Burp extension posts candidate findings to\n"
            "     http://127.0.0.1:<port>/findings (JSON; token header if set).\n"
            "  2. Or paste a raw request in the Inspector tab and run the\n"
            "     selected analyzers locally (passive analysis / probe builder).\n"
            "  3. Confirm or reject candidates in Live findings; export reports.")
        hf = ttk.LabelFrame(self, text=" How it works ", padding=8)
        hf.grid(row=2, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Label(hf, text=hint, justify="left", foreground="#7f849c").pack(anchor="w")

        self.rowconfigure(3, weight=1)

    def _start(self):
        if self.on_start_bridge:
            self.on_start_bridge()

    def _stop(self):
        if self.on_stop_bridge:
            self.on_stop_bridge()

    def collect(self) -> dict:
        return {
            "bridge_port": int(self.port_var.get() or 8737),
            "bridge_token": self.token_var.get(),
            "test_cases": [k for k, v in self.tc_vars.items() if v.get()],
        }

    def set_bridge_status(self, text: str, running: bool):
        self.bridge_status_var.set(text)
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")


class LiveFindingsTab(ttk.Frame):
    """Live candidate findings table with filters + confirm/reject buttons."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.on_confirm = None
        self.on_reject = None
        self.on_clear = None
        self._build()

    def _build(self):
        filt = ttk.Frame(self, style="TFrame")
        filt.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        ttk.Label(filt, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar(value="all")
        ttk.Combobox(filt, textvariable=self.filter_var, state="readonly",
                     values=["all", "candidate", "confirmed", "false_positive"],
                     width=14).pack(side="left", padx=6)

        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        self.tree = make_tree(
            wrap, ("status", "case", "method", "url", "param", "conf", "signal"),
            ("Status", "Test case", "Method", "URL", "Parameter", "Conf.", "Signal"),
            (90, 140, 60, 300, 110, 70, 300))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btns, text="✔ Confirm selected", command=self._confirm).pack(side="left")
        ttk.Button(btns, text="✖ Mark false positive", command=self._reject).pack(
            side="left", padx=6)
        ttk.Button(btns, text="🗑 Clear list", command=self._clear).pack(side="left", padx=6)

    def _confirm(self):
        if self.on_confirm:
            self.on_confirm()

    def _reject(self):
        if self.on_reject:
            self.on_reject()

    def _clear(self):
        if self.on_clear:
            self.on_clear()

    def add_finding(self, f: dict, iid: str):
        case_names = dict(TEST_CASE_LABELS)
        self.tree.insert("", "end", iid=iid, values=(
            f.get("status", ""), case_names.get(f.get("test_case", ""),
                                               f.get("test_case", "")),
            f.get("method", ""), f.get("url", "")[:80],
            f.get("parameter", "") or "—", f.get("confidence", ""),
            (f.get("signal_description", "") or "")[:100]),
            tags=(f.get("status", ""),))

    def update_row_status(self, iid: str, status: str):
        try:
            vals = list(self.tree.item(iid, "values"))
            vals[0] = status
            self.tree.item(iid, values=vals)
        except Exception:
            pass

    def refresh_filter(self, findings_by_iid: dict):
        flt = self.filter_var.get()
        for iid in self.tree.get_children():
            f = findings_by_iid.get(iid)
            if not f:
                continue
            match = flt == "all" or f.get("status") == flt
            self.tree.detach(iid)
            if match:
                self.tree.reattach(iid, "", "end")

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def tag_colors(self):
        self.tree.tag_configure("confirmed", foreground="#a6e3a1")
        self.tree.tag_configure("candidate", foreground="#f9e2af")
        self.tree.tag_configure("false_positive", foreground="#6c7086")


class InspectorTab(ttk.Frame):
    """Manual request analysis + evidence viewer."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(3, weight=1)
        self.on_analyze = None
        self.on_build_probe = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        row0 = ttk.Frame(self, style="TFrame")
        row0.grid(row=0, column=0, sticky="ew", **pad)
        ttk.Button(row0, text="🔎 Analyze pasted request (passive)",
                   style="Accent.TButton", command=self._analyze).pack(side="left")
        ttk.Button(row0, text="🧪 Build active probes (JSON body → canary fields)",
                   command=self._probe).pack(side="left", padx=6)

        reqf = ttk.LabelFrame(self, text=" Raw request "
                                          "(method, url, headers, blank line, body) ",
                              padding=8)
        reqf.grid(row=1, column=0, sticky="ew", **pad)
        wrap_r = ttk.Frame(reqf, style="TFrame")
        wrap_r.pack(fill="both", expand=True)
        self.request_text = add_text(wrap_r, height=8)
        self.request_text.insert("1.0", "POST /api/users HTTP/1.1\n"
                                        "Host: 127.0.0.1:8000\n"
                                        "Content-Type: application/json\n\n"
                                        '{"username": "demo", "email": "d@x.y"}')

        evf = ttk.LabelFrame(self, text=" Evidence / differential ", padding=8)
        evf.grid(row=2, column=0, sticky="nsew", **pad)
        wrap_e = ttk.Frame(evf, style="TFrame")
        wrap_e.pack(fill="both", expand=True)
        self.evidence_text = add_text(wrap_e, height=12)

        prf = ttk.LabelFrame(self, text=" Built probes (send manually via "
                                        "Repeater; then paste responses) ", padding=8)
        prf.grid(row=3, column=0, sticky="nsew", **pad)
        wrap_p = ttk.Frame(prf, style="TFrame")
        wrap_p.pack(fill="both", expand=True)
        self.probe_text = add_text(wrap_p, height=8)

    def _analyze(self):
        if self.on_analyze:
            self.on_analyze()

    def _probe(self):
        if self.on_build_probe:
            self.on_build_probe()

    def set_evidence(self, text: str):
        self.evidence_text.configure(state="normal")
        self.evidence_text.delete("1.0", "end")
        self.evidence_text.insert("1.0", text)
        self.evidence_text.configure(state="disabled")

    def set_probes(self, text: str):
        self.probe_text.configure(state="normal")
        self.probe_text.delete("1.0", "end")
        self.probe_text.insert("1.0", text)
        self.probe_text.configure(state="disabled")

    def get_request(self) -> str:
        return self.request_text.get("1.0", "end").strip()


class ReportsTab(ttk.Frame):
    def __init__(self, master, db=None):
        super().__init__(master, style="TFrame")
        self.db = db
        self.on_export = None
        self.on_import_file = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.tree = make_tree(wrap, ("id", "started", "finished", "name",
                                     "case", "findings"),
                              ("ID", "Started", "Finished", "Session name",
                               "Test case", "Findings"),
                              (44, 140, 140, 220, 160, 80))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        ttk.Button(btns, text="↻ Refresh", command=self.refresh).pack(side="left")
        ttk.Button(btns, text="⬆ Import findings file…", style="Accent.TButton",
                   command=self._import).pack(side="left", padx=6)
        ttk.Button(btns, text="💾 Export session (HTML/CSV/JSON)…",
                   style="Accent.TButton", command=self._export).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Delete session", style="Danger.TButton",
                   command=self._delete).pack(side="left", padx=6)

        hint = ttk.Label(self, text="Reports include confirmed findings and "
                                    "candidates; choose an export folder for the "
                                    "downloaded files.", foreground="#7f849c")
        hint.grid(row=2, column=0, sticky="w", padx=10, pady=(0, 10))

    def refresh(self):
        if not self.db:
            return
        self.tree.delete(*self.tree.get_children())
        for row in self.db.list_sessions():
            self.tree.insert("", "end", values=(
                row["id"], row["started_at"], row["finished_at"] or "",
                row["name"] or "", row["test_case"] or "",
                row["findings_count"] or 0))

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a session first.")
            return None
        return int(self.tree.item(sel[0], "values")[0])

    def _import(self):
        if self.on_import_file:
            self.on_import_file()

    def _export(self):
        sid = self._selected_id()
        if sid is not None and self.on_export:
            self.on_export(sid)

    def _delete(self):
        sid = self._selected_id()
        if sid is None or not self.db:
            return
        if messagebox.askyesno(APP_NAME, f"Delete session #{sid} and its findings?"):
            self.db.delete_session(sid)
            self.refresh()


class ConsoleTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._build()

    def _build(self):
        con = ttk.LabelFrame(self, text=" Console ", padding=4)
        con.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_text = add_text(con, height=20)
        self.log_text.tag_configure("warn", foreground="#f9e2af")
        self.log_text.tag_configure("ok", foreground="#a6e3a1")

    def log(self, line: str, tag: str = ""):
        log_to_text(self.log_text, line, tag)


class SettingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        card = ttk.LabelFrame(self, text=" Portable paths ", padding=10)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        wrap1 = ttk.Frame(card, style="TFrame")
        wrap1.pack(fill="both", expand=True)
        self.paths_text = add_text(wrap1, height=8)
        self.paths_text.insert("1.0", "starting…")

        mem = ttk.LabelFrame(self, text=" Recent memory (memory.md) ", padding=10)
        mem.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        wrap2 = ttk.Frame(mem, style="TFrame")
        wrap2.pack(fill="both", expand=True)
        self.memory_text = add_text(wrap2, height=10)

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
