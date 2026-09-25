"""GUI panels: packet list, protocol detail tree, hex dump.

All widgets live on the Tk main thread. Data enters via ``set_packets`` /
``show_packet`` calls from MainWindow's poll loop.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Optional, Tuple

from ..models import Packet, PROTOCOL_COLORS

MAX_ROWS_DEFAULT = 200_000

COLUMNS = ("no", "time", "src", "dst", "proto", "len", "info")
COLUMN_HEADINGS = {
    "no": ("No.", 60, "w"),
    "time": ("Time", 110, "w"),
    "src": ("Source", 150, "w"),
    "dst": ("Destination", 150, "w"),
    "proto": ("Protocol", 80, "center"),
    "len": ("Length", 70, "e"),
    "info": ("Info", 480, "w"),
}


class PacketListPanel(ttk.Frame):
    """Virtualized-ish Treeview of captured packets with protocol coloring."""

    def __init__(self, master, max_rows: int = MAX_ROWS_DEFAULT,
                 on_select=None, **kw):
        super().__init__(master, **kw)
        self.max_rows = max_rows
        self.on_select = on_select
        self._iid_to_packet: "dict[str, Packet]" = {}
        self._auto_follow = True

        wrap = ttk.Frame(self)
        wrap.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(wrap, columns=COLUMNS, show="headings", selectmode="browse")
        for col in COLUMNS:
            text, width, anchor = COLUMN_HEADINGS[col]
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "info"))
        vsb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        for cls, color in PROTOCOL_COLORS.items():
            self.tree.tag_configure(cls, background=color)
        self.tree.tag_configure("OTHER", background="#eeeeee")

        self.tree.bind("<<TreeviewSelect>>", self._emit_selection)
        self.tree.bind("<Button-1>", self._track_follow, add="+")
        self.tree.bind("<MouseWheel>", self._track_follow_wheel, add="+")

    # -- data ------------------------------------------------------------------
    def append(self, pkt: Packet) -> None:
        row = pkt.summary_row()
        iid = self.tree.insert("", tk.END, values=row, tags=(pkt.color_class(),))
        self._iid_to_packet[iid] = pkt
        if self._auto_follow:
            self.tree.see(iid)
        if len(self._iid_to_packet) > self.max_rows:
            oldest = self.tree.get_children()[0]
            self.tree.delete(oldest)
            self._iid_to_packet.pop(oldest, None)

    def append_batch(self, packets: List[Packet]) -> None:
        for pkt in packets:
            self.append(pkt)

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._iid_to_packet.clear()

    def selected_packet(self) -> Optional[Packet]:
        sel = self.tree.selection()
        return self._iid_to_packet.get(sel[0]) if sel else None

    def packet_count(self) -> int:
        return len(self.tree.get_children())

    # -- selection/follow ---------------------------------------------------------
    def _track_follow(self, _event=None):
        self._auto_follow = True

    def _track_follow_wheel(self, _event=None):
        self._auto_follow = False

    def _emit_selection(self, _event=None):
        pkt = self.selected_packet()
        if pkt and self.on_select:
            self.on_select(pkt)

    def set_auto_follow(self, value: bool) -> None:
        self._auto_follow = value


class DetailTreePanel(ttk.Frame):
    """Protocol-layer field tree for the selected packet."""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.tree = ttk.Treeview(self, columns=("value",), show="tree headings", selectmode="browse")
        self.tree.column("#0", width=220, anchor="w")
        self.tree.column("value", width=520, anchor="w")
        self.tree.heading("#0", text="Field")
        self.tree.heading("value", text="Value")
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def show_packet(self, pkt: Optional[Packet]) -> None:
        self.tree.delete(*self.tree.get_children())
        if pkt is None:
            return
        frame_root = self._insert("", "Frame", {
            "number": pkt.number,
            "captured_len": pkt.frame_len,
            "original_len": pkt.orig_len,
            "timestamp": f"{pkt.timestamp:.6f}",
            "malformed": pkt.malformed,
        })
        for layer in pkt.layers:
            self._insert(frame_root, layer.name, layer.fields)
        self.tree.item(frame_root, open=True)

    def _insert(self, parent, name: str, fields: dict) -> str:
        node = self.tree.insert(parent, tk.END, text=name, values=(f"{len(fields)} fields",), open=False)
        for key, value in fields.items():
            if isinstance(value, bool):
                disp = "1 (True)" if value else "0 (False)"
            elif isinstance(value, list):
                disp = "; ".join(str(x) for x in value[:8])
                if len(value) > 8:
                    disp += f" … (+{len(value) - 8})"
            else:
                disp = str(value)
            self.tree.insert(node, tk.END, text=key, values=(disp,))
        return node


class HexPanel(ttk.Frame):
    """Hex + ASCII dump of the selected packet's raw bytes."""

    BYTES_PER_ROW = 16

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.text = tk.Text(self, wrap=tk.NONE, font=("Consolas", 10),
                            bg="#101418", fg="#d4d4d4", insertbackground="#d4d4d4",
                            height=10, state=tk.DISABLED, undo=False)
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        hsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        for tag, color in (("_off", "#7a7a7a"), ("_asc", "#9cdcfe"), ("_hdr", "#569cd6")):
            self.text.tag_configure(tag, foreground=color)
        self.text.tag_configure("highlight", background="#3a5a8c", foreground="#ffffff")

    def show_packet(self, pkt: Optional[Packet], highlight: Optional[Tuple[int, int]] = None) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        if pkt is None:
            self.text.configure(state=tk.DISABLED)
            return
        raw = pkt.raw
        # header row
        hdr = "offset    " + " ".join(f"{i:02x}" for i in range(self.BYTES_PER_ROW)) + "  |ASCII|"
        self.text.insert(tk.END, hdr + "\n", "_hdr")
        for row_off in range(0, len(raw), self.BYTES_PER_ROW):
            chunk = raw[row_off:row_off + self.BYTES_PER_ROW]
            hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(self.BYTES_PER_ROW * 3 - 1)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.text.insert(tk.END, f"{row_off:08x}  ", "_off")
            self.text.insert(tk.END, hexpart + "  ", ())
            self.text.insert(tk.END, f"|{asc}|\n", "_asc")
        if highlight:
            self._highlight(*highlight)
        self.text.configure(state=tk.DISABLED)

    def _highlight(self, start: int, end: int) -> None:
        """Highlight bytes [start, end) — row-based approximation."""
        start = max(start, 0)
        end = min(end, len(self.text.get("1.0", tk.END)) - 1)
        if end <= start:
            return
        row0 = start // self.BYTES_PER_ROW + 2                  # +2: header + 0-based
        col0 = 10 + (start % self.BYTES_PER_ROW) * 3
        row1 = (end - 1) // self.BYTES_PER_ROW + 2
        col1 = 10 + ((end - 1) % self.BYTES_PER_ROW) * 3 + 2
        try:
            self.text.tag_add("highlight", f"{row0}.{col0}", f"{row1}.{col1}")
        except tk.TclError:
            pass
