"""Alerts tab: filterable alert list with details pane and export."""

import csv
import json
import os
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import filedialog

from ...core.models import SEVERITIES
from ...core.utils import ts_str
from ..widgets import SEV_COLORS, make_tree


class AlertsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        self._build()
        self.load()

    def _build(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))

        ttk.Label(bar, text="Severity:").pack(side="left")
        self.sev_var = tk.StringVar(value="All")
        cb = ttk.Combobox(bar, textvariable=self.sev_var, state="readonly",
                          values=["All"] + list(SEVERITIES), width=10)
        cb.pack(side="left", padx=(2, 8))
        cb.bind("<<ComboboxSelected>>", lambda e: self.load())

        ttk.Label(bar, text="Category:").pack(side="left")
        self.cat_var = tk.StringVar(value="All")
        cb2 = ttk.Combobox(bar, textvariable=self.cat_var, state="readonly",
                           values=["All", "FIM", "PROCESS", "SYSTEM"], width=9)
        cb2.pack(side="left", padx=(2, 8))
        cb2.bind("<<ComboboxSelected>>", lambda e: self.load())

        self.search_var = tk.StringVar()
        ent = ttk.Entry(bar, textvariable=self.search_var, width=26)
        ent.pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Search", command=self.load).pack(side="left", padx=2)
        ttk.Button(bar, text="Reload", command=self.load).pack(side="left", padx=2)

        ttk.Button(bar, text="Ack Selected", command=self._ack).pack(side="right", padx=2)
        ttk.Button(bar, text="Delete Selected", command=self._delete).pack(side="right", padx=2)
        ttk.Button(bar, text="Export CSV", command=lambda: self._export("csv")).pack(side="right", padx=2)
        ttk.Button(bar, text="Export JSON", command=lambda: self._export("json")).pack(side="right", padx=2)

        frame, self.tree = make_tree(self, [
            ("time", "Time", 140, "w"),
            ("sev", "Severity", 85, "center"),
            ("cat", "Category", 85, "center"),
            ("type", "Type", 140, "w"),
            ("title", "Alert", 560, "w"),
            ("ack", "Ack", 45, "center"),
        ], height=15)
        frame.pack(fill="both", expand=True)
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        details = ttk.Labelframe(self, text=" Details ", padding=4)
        details.pack(fill="both", expand=False, pady=(6, 0))
        self.detail = tk.Text(details, height=9, wrap="word",
                              font=("Consolas", 9), state="disabled")
        self.detail.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

    # -- data ---------------------------------------------------------------
    def load(self):
        alerts = self.app.db.alerts(
            severity=self.sev_var.get(),
            category=self.cat_var.get(),
            search=self.search_var.get().strip() or None,
            limit=1000,
        )
        self.tree.delete(*self.tree.get_children())
        for a in alerts:
            self.tree.insert("", "end", iid=str(a.id), values=(
                ts_str(a.timestamp), a.severity, a.category, a.event_type,
                a.title, "✔" if a.acknowledged else ""), tags=(a.severity,))
        self.status_text = f"{len(alerts)} alerts shown"

    def add_alert(self, alert):
        """Live insert from event pump (keeps current filters)."""
        if self.sev_var.get() not in ("All", alert.severity):
            return
        if self.cat_var.get() not in ("All", alert.category):
            return
        self.tree.insert("", 0, iid=str(alert.id), values=(
            ts_str(alert.timestamp), alert.severity, alert.category,
            alert.event_type, alert.title, ""), tags=(alert.severity,))
        if int(self.tree.index("end") - 1) > 1000:
            children = self.tree.get_children()
            self.tree.delete(children[-1])

    def _selected_ids(self):
        return [int(iid) for iid in self.tree.selection()]

    def _show_detail(self, _event=None):
        sel = self.tree.selection()
        self.detail["state"] = "normal"
        self.detail.delete("1.0", "end")
        if sel:
            alerts = self.app.db.alerts(limit=1000)
            wanted = int(sel[0])
            for a in alerts:
                if a.id == wanted:
                    self.detail.insert("1.0", a.details_json())
                    break
        self.detail["state"] = "disabled"

    def _ack(self):
        ids = self._selected_ids()
        for i in ids:
            self.app.db.set_acknowledged(i, 1)
        if ids:
            self.load()

    def _delete(self):
        ids = self._selected_ids()
        if not ids:
            return
        if not messagebox.askyesno("Delete", f"Delete {len(ids)} selected alert(s)?"):
            return
        self.app.db.delete_alerts(ids)
        self.load()

    # -- export ---------------------------------------------------------------
    def _export(self, fmt: str):
        alerts = self.app.db.alerts(
            severity=self.sev_var.get(), category=self.cat_var.get(), limit=100000)
        if not alerts:
            messagebox.showinfo("Export", "Nothing to export with current filters.")
            return
        default = os.path.join(self.app.data_dir, "exports",
                               f"alerts_{ts_str(_time()).replace(':', '').replace(' ', '_')}.{fmt}")
        path = filedialog.asksaveasfilename(
            initialfile=os.path.basename(default),
            initialdir=os.path.dirname(default),
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    w = csv.writer(fh)
                    w.writerow(["timestamp", "iso_time", "severity", "category",
                                "event_type", "title", "acknowledged", "details_json"])
                    for a in alerts:
                        w.writerow([a.timestamp, ts_str(a.timestamp), a.severity,
                                    a.category, a.event_type, a.title,
                                    a.acknowledged, a.details_json()])
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump([a.to_dict() for a in alerts], fh,
                              indent=2, ensure_ascii=False)
            self.app.log_line(f"Exported {len(alerts)} alerts → {path}")
            messagebox.showinfo("Export", f"Exported {len(alerts)} alerts to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


def _time():
    import time
    return time.time()
