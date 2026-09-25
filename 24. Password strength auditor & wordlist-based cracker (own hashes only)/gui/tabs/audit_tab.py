"""Audit tab: load hashes, parse, audit, and browse per-record verdicts."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import parser as parser_mod
from core.policy import audit_all, summarize
from gui import theme


class AuditTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app

        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Label(top, text="Hash input (one per line: hash | hash:salt | "
                            "hash:salt:label | label::hash · # comments ok)",
                  style="Dim.TLabel").pack(anchor="w")

        self.text = tk.Text(top, height=9, bg=theme.PANEL2, fg=theme.FG,
                            insertbackground=theme.FG, relief="flat",
                            font=app.fonts["mono_small"])
        self.text.pack(fill="x", pady=(4, 6))
        self.text.insert(
            "1.0",
            "# Sample (synthetic demo hashes for password/123456/letmein):\n"
            "5f4dcc3b5aa765d61d8327deb882cf99\n"
            "e10adc3949ba59abbe56e057f20f883e\n"
            "0d107d09f5bbe40cade3de5c71e9e9b7:letmein\n")

        btns = ttk.Frame(top)
        btns.pack(fill="x")
        ttk.Button(btns, text="Load from file…", command=self.load_file).pack(side="left")
        ttk.Button(btns, text="Load directory…", command=self.load_dir).pack(side="left", padx=6)
        ttk.Button(btns, text="Parse & Audit", style="Accent.TButton",
                   command=self.parse_audit).pack(side="left", padx=6)
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="left")

        self.summary_var = tk.StringVar(value="No hashes loaded yet.")
        ttk.Label(self, textvariable=self.summary_var, style="Dim.TLabel").pack(
            anchor="w", padx=12, pady=(8, 2))

        cols = ("label", "algo", "digest", "plaintext", "verdict", "entropy", "findings")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        widths = (140, 90, 260, 120, 90, 70, 320)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w", stretch=(c in ("digest", "findings")))
        ysb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        ysb.place(relx=0.99, rely=0.32, relheight=0.55, anchor="ne")

    # -- actions ------------------------------------------------------------

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open hash file", filetypes=[("Hash files", "*.txt *.hash *.csv"), ("All", "*.*")])
        if path:
            self._ingest_path(path)

    def load_dir(self) -> None:
        d = filedialog.askdirectory(title="Open directory of hash files")
        if d:
            for fn in sorted(os.listdir(d)):
                p = os.path.join(d, fn)
                if os.path.isfile(p) and fn.lower().endswith((".txt", ".hash", ".csv")):
                    self._ingest_path(p)

    def _ingest_path(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            messagebox.showerror("HashArmor", f"Cannot read file:\n{exc}")
            return
        cur = self.text.get("1.0", "end").rstrip("\n")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", cur + "\n" + content)

    def parse_audit(self) -> None:
        content = self.text.get("1.0", "end")
        recs = parser_mod.parse_text(content)
        if not recs:
            messagebox.showwarning("HashArmor", "No parseable hashes found.")
            return
        audit_all(recs)
        self.app.set_records(recs, source="audit")
        self.refresh()
        s = summarize(recs)
        self.summary_var.set(
            f"{len(recs)} hashes · "
            + " · ".join(f"{k}: {v}" for k, v in s.items() if v)
            + "   (plaintexts marked CRITICAL were found in builtin weak list)")

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for verdict, color in theme.VERDICT_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color)
        for r in self.app.records:
            self.tree.insert("", "end", values=(
                r.display_name(), r.algo or "?", r.digest_hex,
                r.plaintext or "—", r.verdict or "UNTESTED",
                f"{r.entropy_bits:.1f}" if r.entropy_bits else "—",
                " · ".join(r.findings) if r.findings else "—"),
                tags=(r.verdict or "UNTESTED",))

    def clear(self) -> None:
        self.text.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.summary_var.set("No hashes loaded yet.")
        self.app.set_records([], source="audit")
