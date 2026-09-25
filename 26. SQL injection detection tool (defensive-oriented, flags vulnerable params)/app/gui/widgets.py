"""Dark theme + reusable widgets for the SIDT GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

BG = "#1e1e2e"
BG_ALT = "#27293d"
BG_INPUT = "#16161e"
FG = "#cdd6f4"
FG_DIM = "#7f849c"
ACCENT = "#89b4fa"
ACCENT_HOVER = "#74c7ec"
DANGER = "#f38ba8"
WARN = "#f9e2af"
OK = "#a6e3a1"
BORDER = "#313244"

SEV_COLORS = {
    "critical": "#f38ba8",
    "high": "#f38ba8",
    "medium": "#f9e2af",
    "low": "#a6e3a1",
    "info": "#89b4fa",
}

FONT_FAMILY = "Segoe UI"
FONT = (FONT_FAMILY, 10)
FONT_SM = (FONT_FAMILY, 9)
FONT_MONO = ("Consolas", 9)


def apply_theme(root: tk.Tk) -> None:
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG, foreground=FG, font=FONT)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=FONT)
    style.configure("TLabelframe", background=BG, foreground=FG, bordercolor=BORDER, relief="flat")
    style.configure("TLabelframe.Label", background=BG, foreground=ACCENT, font=(FONT_FAMILY, 10, "bold"))
    style.configure("TButton", background=BG_ALT, foreground=FG, bordercolor=BORDER,
                    padding=(10, 5), focusthickness=0)
    style.map("TButton",
              background=[("active", ACCENT_HOVER), ("pressed", ACCENT)],
              foreground=[("active", "#11111b"), ("disabled", FG_DIM)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#11111b",
                    bordercolor=ACCENT, padding=(12, 6))
    style.map("Accent.TButton",
              background=[("active", ACCENT_HOVER), ("disabled", BG_ALT)],
              foreground=[("disabled", FG_DIM)])
    style.configure("Danger.TButton", background="#c74060", foreground="#ffffff",
                    bordercolor="#c74060", padding=(12, 6))
    style.map("Danger.TButton", background=[("active", DANGER)])
    style.configure("Card.TFrame", background=BG_ALT, bordercolor=BORDER, relief="flat")

    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG,
                    insertcolor=FG, bordercolor=BORDER, padding=4)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])
    style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                    foreground=FG, arrowcolor=FG, bordercolor=BORDER, padding=4)
    style.map("TCombobox", bordercolor=[("focus", ACCENT)],
              fieldbackground=[("readonly", BG_INPUT)])
    style.configure("TCheckbutton", background=BG, foreground=FG, font=FONT)
    style.map("TCheckbutton", background=[("active", BG)])
    style.configure("TSpinbox", fieldbackground=BG_INPUT, foreground=FG,
                    arrowcolor=FG, bordercolor=BORDER)
    style.configure("TNotebook", background=BG, bordercolor=BG, tabmargins=(8, 6, 8, 0))
    style.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM,
                    padding=(14, 7), font=(FONT_FAMILY, 10))
    style.map("TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", "#11111b")])
    style.configure("TProgressbar", background=ACCENT, troughcolor=BG_ALT,
                    bordercolor=BG_ALT, lightcolor=ACCENT, darkcolor=ACCENT)

    style.configure("Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                    foreground=FG, bordercolor=BORDER, rowheight=26, font=FONT_SM)
    style.configure("Treeview.Heading", background=BG_ALT, foreground=FG,
                    bordercolor=BORDER, font=(FONT_FAMILY, 9, "bold"))
    style.map("Treeview", background=[("selected", "#45475a")],
              foreground=[("selected", "#ffffff")])

    root.option_add("*Text.background", BG_INPUT)
    root.option_add("*Text.foreground", FG)
    root.option_add("*Text.insertBackground", FG)
    root.option_add("*Text.selectBackground", ACCENT)
    root.option_add("*Text.selectForeground", "#11111b")
    root.option_add("*Listbox.background", BG_INPUT)
    root.option_add("*Listbox.foreground", FG)
    root.option_add("*Menu.background", BG_ALT)
    root.option_add("*Menu.foreground", FG)
    root.option_add("*Menu.activeBackground", ACCENT)
    root.option_add("*Menu.activeForeground", "#11111b")
    root.option_add("*Scrollbar.background", BG_ALT)
    root.option_add("*Scrollbar.troughcolor", BG_INPUT)
    root.option_add("*Scrollbar.activeBackground", BORDER)


class Card(ttk.Frame):
    def __init__(self, master, title: str = "", **kw):
        super().__init__(master, style="Card.TFrame", **kw)
        self.inner = ttk.Frame(self, style="Card.TFrame")
        self.inner.pack(fill="both", expand=True, padx=10, pady=8)
        if title:
            lbl = ttk.Label(self.inner, text=title, style="TLabel",
                            font=(FONT_FAMILY, 10, "bold"), foreground=ACCENT)
            lbl.pack(anchor="w", pady=(0, 6))


class LabeledEntry(ttk.Frame):
    def __init__(self, master, label: str, default: str = "", width: int = 40, **kw):
        super().__init__(master, style="TFrame", **kw)
        ttk.Label(self, text=label, style="TLabel").pack(anchor="w")
        self.var = tk.StringVar(value=default)
        self.entry = ttk.Entry(self, textvariable=self.var, width=width)
        self.entry.pack(fill="x", pady=(2, 6))

    def get(self) -> str:
        return self.var.get().strip()

    def set(self, value: str) -> None:
        self.var.set(value)


def make_tree(parent, columns, headings, widths, selectmode: str = "browse") -> ttk.Treeview:
    tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode=selectmode)
    for col, head, w in zip(columns, headings, widths):
        tree.heading(col, text=head)
        tree.column(col, width=w, anchor="w", stretch=(w > 200))
    vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    vsb.pack(side="right", fill="y")
    hsb.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    return tree


def add_text(parent, height: int = 5) -> tk.Text:
    txt = tk.Text(parent, height=height, wrap="word",
                  font=FONT_MONO, relief="flat", padx=6, pady=6)
    vsb = ttk.Scrollbar(parent, orient="vertical", command=txt.yview)
    txt.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    txt.pack(fill="both", expand=True)
    return txt


def log_to_text(txt: tk.Text, line: str, tag: str = "") -> None:
    txt.configure(state="normal")
    txt.insert("end", line + "\n", (tag,) if tag else ())
    txt.see("end")
    txt.configure(state="disabled")
