"""Centralized theme: palette, fonts, ttk styling. No magic colors elsewhere."""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

# Dark security-console palette
BG = "#0f1216"        # app background
PANEL = "#1a1f26"     # panel background
PANEL2 = "#12161c"    # deeper panel
BORDER = "#2a313c"
FG = "#d7dde6"        # main text
FG_DIM = "#8a93a3"    # secondary text
ACCENT = "#3ddc84"    # success / green
WARN = "#f7b83d"      # weak / amber
CRIT = "#ff5370"      # critical / red
INFO = "#4dd0e1"      # info / cyan
SELECT = "#24486b"

VERDICT_COLORS = {
    "CRITICAL": CRIT,
    "WEAK": WARN,
    "FAIR": INFO,
    "STRONG": ACCENT,
    "UNTESTED": FG_DIM,
}

MONO_FAMILIES = ("Consolas", "Courier New", "monospace")


def setup(root: tk.Tk) -> dict:
    """Apply ttk styling; return font handles."""
    style = tk.ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    base = tkfont.nametofont("TkDefaultFont")
    base.configure(size=10)
    mono_family = next((f for f in MONO_FAMILIES if f in tkfont.families()), "TkFixedFont")
    mono = tkfont.Font(family=mono_family, size=10)
    mono_small = tkfont.Font(family=mono_family, size=9)

    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL2,
                    bordercolor=BORDER, lightcolor=PANEL, darkcolor=BG,
                    troughcolor=PANEL2, selectbackground=SELECT,
                    selectforeground=FG, font=base)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Panel.TLabel", background=PANEL, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=FG_DIM)
    style.configure("Title.TLabel", background=BG, foreground=FG,
                    font=(base.actual("family"), 13, "bold"))
    style.configure("TLabelframe", background=BG, foreground=FG, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=FG_DIM)
    style.configure("TButton", background=PANEL, foreground=FG, padding=(10, 5))
    style.map("TButton",
              background=[("active", SELECT), ("disabled", PANEL2)],
              foreground=[("disabled", FG_DIM)])
    style.configure("Accent.TButton", background="#173d2a", foreground=ACCENT)
    style.map("Accent.TButton",
              background=[("active", "#1d5236"), ("disabled", PANEL2)],
              foreground=[("disabled", FG_DIM)])
    style.configure("Danger.TButton", background="#3a1520", foreground=CRIT)
    style.map("Danger.TButton", background=[("active", "#571b2c")])
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.map("TCheckbutton", background=[("active", BG)])
    style.configure("TRadiobutton", background=BG, foreground=FG)
    style.map("TRadiobutton", background=[("active", BG)])
    style.configure("TEntry", fieldbackground=PANEL2, foreground=FG,
                    insertcolor=FG, bordercolor=BORDER)
    style.configure("TCombobox", fieldbackground=PANEL2, foreground=FG,
                    arrowcolor=FG)
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=FG_DIM,
                    padding=(14, 6))
    style.map("TNotebook.Tab",
              background=[("selected", SELECT)],
              foreground=[("selected", FG)])
    style.configure("Horizontal.TProgressbar", background=ACCENT,
                    troughcolor=PANEL2, bordercolor=BG, lightcolor=ACCENT,
                    darkcolor=ACCENT)
    style.configure("Treeview", background=PANEL2, foreground=FG,
                    fieldbackground=PANEL2, rowheight=22, bordercolor=BORDER)
    style.configure("Treeview.Heading", background=PANEL, foreground=FG_DIM)
    style.map("Treeview", background=[("selected", SELECT)],
              foreground=[("selected", FG)])

    return {"base": base, "mono": mono, "mono_small": mono_small}
