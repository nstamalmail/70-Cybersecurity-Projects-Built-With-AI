"""Statistics panel: session counters, protocol distribution, top talkers."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from ..capture.stats import StatisticsSnapshot


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,.0f} B"
        n /= 1024
    return f"{n:,.1f} TB"


class StatisticsPanel(ttk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self._build()

    def _build(self) -> None:
        top = ttk.LabelFrame(self, text="Session")
        top.pack(side=tk.TOP, fill=tk.X, padx=6, pady=4)
        self.lbl_total = ttk.Label(top, text="Packets: 0")
        self.lbl_matched = ttk.Label(top, text="Matched filter: 0")
        self.lbl_dropped = ttk.Label(top, text="Dropped (queue full): 0")
        self.lbl_bytes = ttk.Label(top, text="Bytes: 0 B")
        self.lbl_rate = ttk.Label(top, text="Rate: 0 pps / 0 bps")
        self.lbl_elapsed = ttk.Label(top, text="Elapsed: 0s")
        for i, w in enumerate((self.lbl_total, self.lbl_matched, self.lbl_dropped)):
            w.grid(row=0, column=i, sticky="w", padx=8, pady=2)
        for i, w in enumerate((self.lbl_bytes, self.lbl_rate, self.lbl_elapsed)):
            w.grid(row=1, column=i, sticky="w", padx=8, pady=2)
        top.columnconfigure((0, 1, 2), weight=1)

        mid = ttk.LabelFrame(self, text="Protocol distribution")
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.proto_tree = ttk.Treeview(mid, columns=("count", "pct"), show="tree headings", height=8)
        self.proto_tree.column("#0", width=180, anchor="w")
        self.proto_tree.column("count", width=100, anchor="e")
        self.proto_tree.column("pct", width=80, anchor="e")
        self.proto_tree.heading("#0", text="Protocol")
        self.proto_tree.heading("count", text="Packets")
        self.proto_tree.heading("pct", text="%")
        vsb = ttk.Scrollbar(mid, orient=tk.VERTICAL, command=self.proto_tree.yview)
        self.proto_tree.configure(yscrollcommand=vsb.set)
        self.proto_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        bot = ttk.LabelFrame(self, text="Top talkers (src+dst appearances)")
        bot.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.talk_tree = ttk.Treeview(bot, columns=("count",), show="tree headings", height=8)
        self.talk_tree.column("#0", width=280, anchor="w")
        self.talk_tree.column("count", width=80, anchor="e")
        self.talk_tree.heading("#0", text="Host")
        self.talk_tree.heading("count", text="Packets")
        vsb2 = ttk.Scrollbar(bot, orient=tk.VERTICAL, command=self.talk_tree.yview)
        self.talk_tree.configure(yscrollcommand=vsb2.set)
        self.talk_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb2.pack(side=tk.RIGHT, fill=tk.Y)

    # -- update ---------------------------------------------------------------
    def update_stats(self, snap: StatisticsSnapshot) -> None:
        self.lbl_total.config(text=f"Packets: {snap.total:,}")
        self.lbl_matched.config(text=f"Matched filter: {snap.matched:,}")
        self.lbl_dropped.config(text=f"Dropped (queue full): {snap.dropped:,}")
        self.lbl_bytes.config(text=f"Bytes: {_human_bytes(snap.bytes_total)}")
        self.lbl_rate.config(text=f"Rate: {snap.pps:,.0f} pps / {_human_bytes(snap.bps)}/s")
        self.lbl_elapsed.config(text=f"Elapsed: {snap.elapsed:,.0f}s")

        self.proto_tree.delete(*self.proto_tree.get_children())
        for proto, count in sorted(snap.protocol_counts.items(), key=lambda kv: -kv[1]):
            pct = (count / snap.total * 100) if snap.total else 0.0
            self.proto_tree.insert("", tk.END, text=proto,
                                   values=(f"{count:,}", f"{pct:.1f}%"))

        self.talk_tree.delete(*self.talk_tree.get_children())
        for host, count in snap.top_talkers:
            self.talk_tree.insert("", tk.END, text=host, values=(f"{count:,}",))

    def clear(self) -> None:
        self.proto_tree.delete(*self.proto_tree.get_children())
        self.talk_tree.delete(*self.talk_tree.get_children())
