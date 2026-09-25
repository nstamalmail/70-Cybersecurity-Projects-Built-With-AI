"""Shared UI helpers: read-only label grids and treeview clipboard copy."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..app import UserError


def show_error(root: tk.Misc, message: str) -> None:
    """Non-blocking-friendly error surfacing: status bar if available else dialog."""
    import tkinter.messagebox as messagebox

    messagebox.showerror("VLSM Planner", message, parent=root)


def grid_of_labels(
    parent: tk.Widget,
    rows: list[tuple[str, str]],
    label_width: int = 18,
    value_width: int = 40,
) -> dict[str, tk.StringVar]:
    """Render a read-only two-column grid; returns {key: StringVar}."""
    vars_: dict[str, tk.StringVar] = {}
    for row, (key, label) in enumerate(rows):
        tk.Label(parent, text=label, anchor="w", width=label_width).grid(
            row=row, column=0, sticky="w", padx=(4, 8), pady=1
        )
        var = tk.StringVar(value="")
        entry = ttk.Entry(parent, textvariable=var, width=value_width, state="readonly")
        entry.grid(row=row, column=1, sticky="w", padx=(0, 4), pady=1)
        vars_[key] = var
    return vars_


def copy_selection_to_clipboard(widget: tk.Misc, tree: ttk.Treeview,
                                columns: tuple[str, ...]) -> None:
    """Copy the selected treeview row as tab-separated text (Ctrl+C friendly)."""
    selection = tree.selection()
    if not selection:
        return
    lines = []
    for item_id in selection:
        values = tree.item(item_id, "values")
        lines.append("\t".join(str(v) for v in values))
    widget.clipboard_clear()
    widget.clipboard_append("\n".join(lines))


def bind_copy(widget: tk.Misc, tree: ttk.Treeview, columns: tuple[str, ...]) -> None:
    """Attach Ctrl+C copy plus a right-click context menu to a treeview."""
    def _on_ctrl_c(event: tk.Event) -> str:
        copy_selection_to_clipboard(widget, tree, columns)
        return "break"

    def _menu(event: tk.Event) -> None:
        item = tree.identify_row(event.y)
        if item:
            tree.selection_set(item)
            menu = tk.Menu(widget, tearoff=0)
            menu.add_command(
                label="Copy row",
                command=lambda: copy_selection_to_clipboard(widget, tree, columns),
            )
            menu.tk_popup(event.x_root, event.y_root)

    tree.bind("<Control-c>", _on_ctrl_c)
    tree.bind("<Button-3>", _menu)


def set_status(var: tk.StringVar, text: str) -> None:
    var.set(text)


def unwrap_user_error(fn):
    """Decorator: re-raise UserError as-is, wrap anything else generically."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except UserError:
            raise
        except Exception as exc:  # noqa: BLE001 - defensive catch-all for GUI
            import logging

            logging.getLogger("vlsm.ui").exception("unexpected UI error")
            raise UserError(f"Unexpected error: {exc}") from exc

    return wrapper