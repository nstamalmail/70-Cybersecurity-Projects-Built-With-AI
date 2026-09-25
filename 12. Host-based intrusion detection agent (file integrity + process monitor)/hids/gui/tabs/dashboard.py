"""Dashboard: KPI cards, severity distribution chart, recent alerts."""

import tkinter as tk
from tkinter import ttk

from ...core.models import SEVERITIES
from ...core.utils import ts_str
from ..widgets import SEV_COLORS, StatCard, make_tree


class DashboardTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        self._build()
        self.refresh_stats()

    def _build(self):
        cards = ttk.Frame(self)
        cards.pack(fill="x")
        self.card_files = StatCard(cards, "Files monitored", "0", "#0f4c81")
        self.card_alerts = StatCard(cards, "Total alerts", "0", "#2e7d32")
        self.card_crit = StatCard(cards, "Critical / High", "0", "#c62828")
        self.card_susp = StatCard(cards, "Suspicious processes", "0", "#e65100",
                                  "in last snapshot")
        for c in (self.card_files, self.card_alerts, self.card_crit, self.card_susp):
            c.pack(side="left", fill="both", expand=True, padx=4, pady=4)

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, pady=(10, 0))

        chart_box = ttk.Labelframe(body, text=" Alerts by severity ", padding=8)
        chart_box.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.canvas = tk.Canvas(chart_box, height=200, bg="#ffffff",
                                highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self._draw_chart())

        recent = ttk.Labelframe(body, text=" Recent alerts ", padding=4)
        recent.pack(side="left", fill="both", expand=True, padx=(6, 0))
        frame, self.recent_tree = make_tree(recent, [
            ("time", "Time", 130, "w"),
            ("sev", "Severity", 80, "center"),
            ("title", "Alert", 520, "w"),
        ], height=10)
        frame.pack(fill="both", expand=True)
        self.recent_tree.tag_configure("CRITICAL", foreground=SEV_COLORS["CRITICAL"])
        self.recent_tree.tag_configure("HIGH", foreground=SEV_COLORS["HIGH"])
        self.recent_tree.tag_configure("MEDIUM", foreground=SEV_COLORS["MEDIUM"])

    # -- data -------------------------------------------------------------
    def refresh_stats(self):
        counts = self.app.db.alert_counts()
        self.card_alerts.set(counts.get("TOTAL", 0))
        crit = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        self.card_crit.set(crit)
        self.card_files.set(self.app.db.baseline_count(),
                            f"baseline built {ts_str(float(self.app.db.get_meta('baseline_built') or 0)) if self.app.db.get_meta('baseline_built') else '—'}")
        self.card_susp.set(getattr(self.app.proc, "suspicious_count", 0) or 0)
        self._draw_chart()
        self._load_recent()

    def on_alert(self, alert):
        self.recent_tree.insert("", 0, values=(
            ts_str(alert.timestamp), alert.severity, alert.title),
            tags=(alert.severity,))
        if self.recent_tree and len(self.recent_tree.get_children()) > 60:
            self.recent_tree.delete(self.recent_tree.get_children()[-1])
        self.refresh_stats()

    def on_scan(self):
        self.refresh_stats()

    def _load_recent(self):
        self.recent_tree.delete(*self.recent_tree.get_children())
        for a in self.app.db.alerts(limit=50):
            self.recent_tree.insert("", "end", values=(
                ts_str(a.timestamp), a.severity, a.title), tags=(a.severity,))

    def _draw_chart(self):
        canvas = self.canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 320)
        height = max(canvas.winfo_height(), 180)
        counts = self.app.db.alert_counts()
        data = [(s, counts.get(s, 0)) for s in SEVERITIES]
        max_v = max([v for _, v in data] + [1])
        pad, bar_w = 40, 48
        gap = (width - pad * 2 - bar_w * len(data)) / (len(data) + 1)
        baseline = height - 30
        # grid lines
        for i in range(1, 5):
            y = baseline - (baseline - 15) * i / 4
            canvas.create_line(pad, y, width - pad, y, fill="#e0e0e0")
        for i, (sev, val) in enumerate(data):
            x = pad + gap * (i + 1) + bar_w * i
            h = (baseline - 15) * val / max_v
            canvas.create_rectangle(x, baseline - h, x + bar_w, baseline,
                                    fill=SEV_COLORS[sev], outline="")
            canvas.create_text(x + bar_w / 2, baseline + 12, text=sev,
                               font=("Segoe UI", 8))
            if val:
                canvas.create_text(x + bar_w / 2, baseline - h - 8, text=str(val),
                                   font=("Segoe UI", 9, "bold"))
