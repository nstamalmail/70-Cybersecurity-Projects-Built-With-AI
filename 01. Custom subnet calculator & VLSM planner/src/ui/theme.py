"""Light/dark theming engine for the tkinter UI.

Why "clam": the Windows "vista" theme only supports partial styling, while
the cross-platform "clam" theme exposes full control (hover states, field
backgrounds, notebook tabs, scrollbars), which is required for a coherent
dark theme.

tk.Menu widgets do not participate in ttk styles, so they are themed via
root.option_add (Tk option database). Treeview rows get even/odd striping
through per-item tags; selection is preserved by re-tagging on
<<TreeviewSelect>> because tag backgrounds otherwise override the selection
highlight.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict, Sequence

DEFAULT_THEME = "light"
VALID_THEMES = ("light", "dark")

LIGHT: Dict[str, str] = {
    "bg": "#f3f3f3",
    "surface": "#fafafa",
    "surface_alt": "#ffffff",
    "text": "#1a1a1a",
    "muted": "#5f5f5f",
    "border": "#c9c9c9",
    "accent": "#0078d4",
    "accent_text": "#ffffff",
    "accent_hover": "#106ebe",
    "button_hover": "#e8f0fa",
    "input": "#ffffff",
    "input_disabled": "#efefef",
    "selection": "#cce4f7",
    "selection_text": "#0b2b40",
    "tree_even": "#ffffff",
    "tree_odd": "#f4f6f8",
    "tree_heading": "#ececec",
    "scrollbar": "#b8b8b8",
    "trough": "#e2e2e2",
    "menu_bg": "#ffffff",
    "menu_fg": "#1a1a1a",
    "menu_active": "#0078d4",
    "menu_active_text": "#ffffff",
}

DARK: Dict[str, str] = {
    "bg": "#1b1d1f",
    "surface": "#232527",
    "surface_alt": "#2b2d30",
    "text": "#d8d8d8",
    "muted": "#9d9d9d",
    "border": "#3a3d42",
    "accent": "#0a84ff",
    "accent_text": "#ffffff",
    "accent_hover": "#2b95ff",
    "button_hover": "#33373b",
    "input": "#2f3136",
    "input_disabled": "#26282b",
    "selection": "#264f78",
    "selection_text": "#ffffff",
    "tree_even": "#232527",
    "tree_odd": "#27292d",
    "tree_heading": "#2f3136",
    "scrollbar": "#4a4d52",
    "trough": "#1f2123",
    "menu_bg": "#2b2d30",
    "menu_fg": "#d8d8d8",
    "menu_active": "#0a84ff",
    "menu_active_text": "#ffffff",
}

PALETTES = {"light": LIGHT, "dark": DARK}


def apply_theme(
    root: tk.Misc, mode: str, treeviews: Sequence[ttk.Treeview] = ()
) -> str:
    """Apply the named palette; returns the effective mode."""
    mode = mode if mode in PALETTES else DEFAULT_THEME
    palette = PALETTES[mode]

    style = ttk.Style(root)
    style.theme_use("clam")
    _configure_styles(style, palette)
    _configure_tk_options(root, palette)
    root.configure(bg=palette["bg"])

    for tree in treeviews:
        _configure_tree_tags(tree, palette)
        restripe_tree(tree)
    return mode


def _configure_styles(style: ttk.Style, p: Dict[str, str]) -> None:
    style.configure(".", font=("Segoe UI", 10))

    style.configure("TFrame", background=p["bg"])
    style.configure("TLabel", background=p["bg"], foreground=p["text"])
    style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])

    style.configure(
        "TButton",
        background=p["surface_alt"],
        foreground=p["text"],
        bordercolor=p["border"],
        borderwidth=1,
        relief="flat",
        padding=(12, 6),
    )
    style.map(
        "TButton",
        background=[("active", p["button_hover"]), ("disabled", p["surface_alt"])],
        foreground=[("disabled", p["muted"])],
    )
    style.configure(
        "Accent.TButton",
        background=p["accent"],
        foreground=p["accent_text"],
        bordercolor=p["accent"],
        borderwidth=1,
        relief="flat",
        padding=(12, 6),
    )
    style.map(
        "Accent.TButton",
        background=[("active", p["accent_hover"]), ("disabled", p["trough"])],
        foreground=[("disabled", p["muted"])],
    )

    entry_opts = dict(
        fieldbackground=p["input"],
        foreground=p["text"],
        bordercolor=p["border"],
        lightcolor=p["border"],
        darkcolor=p["border"],
        insertcolor=p["text"],
        padding=(6, 5),
    )
    style.configure("TEntry", **entry_opts)
    style.configure("TCombobox", **entry_opts, arrowcolor=p["muted"])
    style.map(
        "TEntry",
        fieldbackground=[
            ("readonly", p["input_disabled"]),
            ("disabled", p["input_disabled"]),
        ],
        foreground=[("readonly", p["muted"]), ("disabled", p["muted"])],
    )
    style.map(
        "TCombobox",
        fieldbackground=[
            ("readonly", p["input_disabled"]),
            ("disabled", p["input_disabled"]),
        ],
        foreground=[("readonly", p["muted"]), ("disabled", p["muted"])],
    )

    style.configure("TNotebook", background=p["bg"], borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=p["surface_alt"],
        foreground=p["muted"],
        borderwidth=0,
        padding=(14, 7),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", p["surface"])],
        foreground=[("selected", p["text"]), ("active", p["text"])],
    )

    style.configure(
        "Treeview",
        background=p["tree_even"],
        fieldbackground=p["tree_even"],
        foreground=p["text"],
        bordercolor=p["border"],
        rowheight=24,
    )
    style.map(
        "Treeview",
        background=[("selected", p["selection"])],
        foreground=[("selected", p["selection_text"])],
    )
    style.configure(
        "Treeview.Heading",
        background=p["tree_heading"],
        foreground=p["text"],
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        padding=(6, 5),
    )
    style.map("Treeview.Heading", background=[("active", p["tree_heading"])])

    for orient in ("Vertical", "Horizontal"):
        style.configure(
            f"{orient}.TScrollbar",
            background=p["scrollbar"],
            troughcolor=p["trough"],
            bordercolor=p["trough"],
            arrowcolor=p["muted"],
            relief="flat",
        )

    style.configure(
        "TLabelframe",
        background=p["surface"],
        bordercolor=p["border"],
        relief="solid",
        borderwidth=1,
    )
    style.configure("TLabelframe.Label", background=p["surface"], foreground=p["text"])

    style.configure(
        "Status.TLabel",
        background=p["surface_alt"],
        foreground=p["text"],
        relief="sunken",
        padding=(6, 3),
    )


def _configure_tk_options(root: tk.Misc, p: Dict[str, str]) -> None:
    """Theme classic-tk widgets (Labels, Menus) via the option database."""
    root.option_add("*Label.background", p["surface"])
    root.option_add("*Label.foreground", p["text"])
    root.option_add("*Menu.background", p["menu_bg"])
    root.option_add("*Menu.foreground", p["menu_fg"])
    root.option_add("*Menu.activeBackground", p["menu_active"])
    root.option_add("*Menu.activeForeground", p["menu_active_text"])
    root.option_add("*Menu.selectColor", p["menu_active"])
    root.option_add("*Menubutton.background", p["surface_alt"])
    root.option_add("*Menubutton.foreground", p["text"])
    root.option_add("*TCombobox*Listbox.background", p["input"])
    root.option_add("*TCombobox*Listbox.foreground", p["text"])


# --------------------------------------------------------------------------
# Treeview row striping
# --------------------------------------------------------------------------

def _configure_tree_tags(tree: ttk.Treeview, p: Dict[str, str]) -> None:
    tree.tag_configure("even", background=p["tree_even"])
    tree.tag_configure("odd", background=p["tree_odd"])
    tree.tag_configure(
        "selected", background=p["selection"], foreground=p["selection_text"]
    )


def restripe_tree(tree: ttk.Treeview) -> None:
    """Re-apply even/odd tags (keeps the current selection highlighted).

    Safe to call after any population of the tree; the <<TreeviewSelect>>
    handler is bound only once.
    """
    if not getattr(tree, "_stripe_bound", False):
        tree.bind("<<TreeviewSelect>>", lambda _e: _restripe(tree), add="+")
        tree._stripe_bound = True
    _restripe(tree)


def _restripe(tree: ttk.Treeview) -> None:
    selected = set(tree.selection())
    for index, item in enumerate(tree.get_children()):
        if item in selected:
            tag = "selected"
        else:
            tag = "even" if index % 2 == 0 else "odd"
        tree.item(item, tags=(tag,))