"""Reusable tkinter helpers for the workbench panels.

Everything here is plain tkinter/ttk — no external chart library required.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

VERDICT_COLORS = {"malicious": "#c62828", "suspicious": "#ef6c00", "clean": "#2e7d32"}


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB"):
        if n < 1024 or unit == "MiB":
            return f"{n} {unit}" if unit == "B" else f"{n / 1024:.1f} {unit}"
    return f"{n} B"


def make_tree(parent, columns, headings, widths):
    """Treeview + scrollbars. Returns (frame, tree)."""
    outer = ttk.Frame(parent)
    outer.rowconfigure(0, weight=1)
    outer.columnconfigure(0, weight=1)
    tree = ttk.Treeview(outer, columns=columns, show="headings", selectmode="browse")
    for col, head, w in zip(columns, headings, widths):
        tree.heading(col, text=head)
        tree.column(col, width=w, anchor="w", stretch=(w >= 200))
    ysb = ttk.Scrollbar(outer, orient="vertical", command=tree.yview)
    xsb = ttk.Scrollbar(outer, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    ysb.grid(row=0, column=1, sticky="ns")
    xsb.grid(row=1, column=0, sticky="ew")
    return outer, tree


def make_text(parent, height: int = 6):
    """Read-only text box with scrollbar. Returns (frame, text)."""
    outer = ttk.Frame(parent)
    outer.rowconfigure(0, weight=1)
    outer.columnconfigure(0, weight=1)
    txt = tk.Text(outer, height=height, wrap="word", state="disabled",
                  font=("Consolas", 10), background="#fafafa")
    ysb = ttk.Scrollbar(outer, orient="vertical", command=txt.yview)
    txt.configure(yscrollcommand=ysb.set)
    txt.grid(row=0, column=0, sticky="nsew")
    ysb.grid(row=0, column=1, sticky="ns")
    return outer, txt


def set_text(txt: tk.Text, content: str) -> None:
    txt.configure(state="normal")
    txt.delete("1.0", "end")
    txt.insert("1.0", content)
    txt.configure(state="disabled")


def chunked_insert(tree: ttk.Treeview, rows, chunk: int = 500, after_ms: int = 10) -> None:
    """Insert (values, tag) rows in idle-time chunks to keep the UI responsive."""
    tree.delete(*tree.get_children())

    def step(lo: int) -> None:
        hi = min(lo + chunk, len(rows))
        for values, tag in rows[lo:hi]:
            if tag:
                tree.insert("", "end", values=values, tags=(tag,))
            else:
                tree.insert("", "end", values=values)
        if hi < len(rows):
            tree.after(after_ms, lambda: step(hi))

    step(0)


def style_verdict_tags(tree: ttk.Treeview) -> None:
    for name, color in VERDICT_COLORS.items():
        tree.tag_configure(name, background=color, foreground="#ffffff")


def draw_pie(canvas: tk.Canvas, counts: dict, size: int = 150) -> None:
    """Verdict pie chart on a plain tk.Canvas (no matplotlib dependency)."""
    canvas.delete("all")
    total = sum(counts.values())
    w = int(canvas.winfo_width() or size)
    h = int(canvas.winfo_height() or size)
    x0, y0 = 10, 10
    x1, y1 = x0 + size, y0 + size
    if not total:
        canvas.create_oval(x0, y0, x1, y1, outline="#9e9e9e", fill="#eeeeee")
        canvas.create_text((x0 + x1) / 2, (y0 + y1) / 2, text="no data", fill="#616161")
        return
    start = 90.0
    for key in ("malicious", "suspicious", "clean"):
        n = counts.get(key, 0)
        if not n:
            continue
        extent = 360.0 * n / total
        canvas.create_arc(x0, y0, x1, y1, start=start, extent=-extent,
                          fill=VERDICT_COLORS[key], outline="white", width=2,
                          style=tk.PIESLICE)
        start -= extent
    legend_y = y0 + 8
    for key in ("malicious", "suspicious", "clean"):
        n = counts.get(key, 0)
        color = VERDICT_COLORS[key]
        canvas.create_rectangle(x1 + 16, legend_y, x1 + 30, legend_y + 12,
                                fill=color, outline="")
        canvas.create_text(x1 + 36, legend_y + 6, anchor="w", fill="#212121",
                           text=f"{key}: {n}")
        legend_y += 20


def draw_timeline(canvas: tk.Canvas, flows, findings, width: int = 900, height: int = 90) -> None:
    """Scenario timeline strip: flow density + malicious hits as red ticks."""
    canvas.delete("all")
    if not flows:
        canvas.create_text(width / 2, height / 2, text="no data", fill="#616161")
        return
    t_min = flows[0].ts
    t_max = max(f.ts for f in flows) or (t_min + 1)
    span = (t_max - t_min) or 1.0
    buckets = [0] * width
    malicious_x = []
    for i, f in enumerate(flows):
        x = int((f.ts - t_min) / span * (width - 20)) + 10
        buckets[min(max(x, 10), width - 10)] += 1
        if f.verdict == "malicious":
            malicious_x.append(x)
    peak = max(buckets) or 1
    for x, n in enumerate(buckets):
        if n:
            bh = int(n / peak * (height - 30))
            canvas.create_line(x, height - 5, x, height - 5 - bh, fill="#90a4ae")
    for x in malicious_x:
        canvas.create_line(x, 5, x, 18, fill="#c62828", width=2)
    canvas.create_text(12, 8, anchor="w", text="traffic density", fill="#455a64",
                       font=("Segoe UI", 8))
    canvas.create_text(width - 12, 8, anchor="e", text="red = malicious", fill="#c62828",
                       font=("Segoe UI", 8))
