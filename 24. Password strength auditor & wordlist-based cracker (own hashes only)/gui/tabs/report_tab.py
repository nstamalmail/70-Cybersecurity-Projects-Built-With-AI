"""Report tab: export HTML/CSV/JSON and preview the HTML report in-window."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.exporter import export_csv, export_html, export_json
from core.policy import summarize
from gui import theme


class ReportTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app
        self.last_html: str | None = None

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        ttk.Label(bar, text="Exports are written to the folder you choose and carry "
                            "the authorization watermark.", style="Dim.TLabel").pack(
            side="left")

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=12, pady=4)
        ttk.Button(btns, text="Export HTML report…", style="Accent.TButton",
                   command=self.export_html).pack(side="left")
        ttk.Button(btns, text="Export CSV…",
                   command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="Export JSON…",
                   command=self.export_json).pack(side="left")
        self.open_btn = ttk.Button(btns, text="Open in browser",
                                   command=self.open_browser, state="disabled")
        self.open_btn.pack(side="left", padx=6)

        self.preview = tk.Text(self, bg=theme.PANEL2, fg=theme.FG, relief="flat",
                               font=self.app.fonts["mono_small"], wrap="none")
        self.preview.pack(fill="both", expand=True, padx=12, pady=(6, 12))
        self.preview.insert("1.0",
                            "Run Parse & Audit (and optionally an attack), then export "
                            "the HTML report here or open it in your browser.\n\n"
                            "The HTML file is fully self-contained (no CDN, no JS "
                            "dependencies) and can be shared inside your team freely — "
                            "it contains only what you choose to include.")
        self.preview.configure(state="disabled")

    def export_html(self) -> None:
        if not self.app.records:
            messagebox.showwarning("HashArmor", "Nothing to export yet — run an audit first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML report", "*.html")],
            initialfile="hasharmor_report.html")
        if not path:
            return
        try:
            export_html(path, self.app.records,
                        meta={"records": len(self.app.records)})
            self.last_html = os.path.abspath(path)
            self.open_btn.configure(state="normal")
            self._show_summary(f"HTML report written:\n{self.last_html}")
        except OSError as exc:
            messagebox.showerror("HashArmor", f"Export failed:\n{exc}")

    def export_csv(self) -> None:
        if not self.app.records:
            messagebox.showwarning("HashArmor", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="hasharmor_report.csv")
        if not path:
            return
        try:
            export_csv(path, self.app.records)
            self._show_summary(f"CSV written:\n{os.path.abspath(path)}")
        except OSError as exc:
            messagebox.showerror("HashArmor", f"Export failed:\n{exc}")

    def export_json(self) -> None:
        if not self.app.records:
            messagebox.showwarning("HashArmor", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile="hasharmor_report.json")
        if not path:
            return
        try:
            export_json(path, self.app.records)
            self._show_summary(f"JSON written:\n{os.path.abspath(path)}")
        except OSError as exc:
            messagebox.showerror("HashArmor", f"Export failed:\n{exc}")

    def _show_summary(self, message: str) -> None:
        s = summarize(self.app.records)
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", message + "\n\nSummary: " + " · ".join(
            f"{k}: {v}" for k, v in s.items() if v))
        self.preview.configure(state="disabled")
        self.app.set_status("Report exported.")

    def open_browser(self) -> None:
        if self.last_html and os.path.isfile(self.last_html):
            import webbrowser
            webbrowser.open("file:///" + self.last_html.replace("\\", "/"))

    def preview_reset_hint(self) -> None:
        self.last_html = None
        self.open_btn.configure(state="disabled")
