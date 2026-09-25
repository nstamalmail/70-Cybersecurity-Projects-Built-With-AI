"""Shared GUI widgets and style constants."""

import tkinter as tk
from tkinter import ttk

SEV_COLORS = {
    "CRITICAL": "#c62828",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#1565c0",
    "INFO": "#616161",
}

ACCENT = "#0f4c81"
BG = "#f4f6f8"


class StatCard(ttk.Frame):
    """KPI card: title, big value, optional subtitle."""

    def __init__(self, parent, title: str, value: str = "0",
                 color: str = ACCENT, subtitle: str = ""):
        super().__init__(parent, padding=10, style="Card.TFrame")
        self._value_var = tk.StringVar(value=value)
        self._sub_var = tk.StringVar(value=subtitle)

        ttk.Label(self, text=title.upper(), style="CardTitle.TLabel").pack(anchor="w")
        tk.Label(self, textvariable=self._value_var, fg=color, bg="#ffffff",
                 font=("Segoe UI", 20, "bold"), anchor="w").pack(fill="x", anchor="w")
        ttk.Label(self, textvariable=self._sub_var, style="CardSub.TLabel").pack(anchor="w")

    def set(self, value, subtitle: str = "") -> None:
        self._value_var.set(str(value))
        if subtitle:
            self._sub_var.set(subtitle)


def make_tree(parent, columns, height=12):
    """Treeview with vertical scrollbar; returns (tree, scrollbar)."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns],
                        show="headings", height=height)
    for cid, text, width, anchor in columns:
        tree.heading(cid, text=text)
        tree.column(cid, width=width, anchor=anchor, stretch=True)
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, tree
