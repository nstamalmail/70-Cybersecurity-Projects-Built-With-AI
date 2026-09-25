"""Shared UI helpers — small labeled form fields and text conveniences."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

MONO = ("Consolas", 10)


def labeled_entry(parent, label: str, width: int = 30, default: str = "") -> tuple[ttk.Frame, tk.StringVar]:
    """Return (frame, var) for a labeled entry row."""
    frame = ttk.Frame(parent)
    ttk.Label(frame, text=label, width=16, anchor="e").pack(side="left", padx=(0, 6))
    var = tk.StringVar(value=default)
    ttk.Entry(frame, textvariable=var, width=width).pack(side="left", fill="x", expand=True)
    return frame, var


def labeled_spin(
    parent, label: str, from_: int, to: int, default: int, width: int = 8
) -> tuple[ttk.Frame, tk.IntVar]:
    frame = ttk.Frame(parent)
    ttk.Label(frame, text=label, width=16, anchor="e").pack(side="left", padx=(0, 6))
    var = tk.IntVar(value=default)
    ttk.Spinbox(frame, from_=from_, to=to, textvariable=var, width=width).pack(side="left")
    return frame, var


def labeled_combo(parent, label: str, values: list[str], default: str = "", width: int = 30) -> tuple[ttk.Frame, tk.StringVar]:
    frame = ttk.Frame(parent)
    ttk.Label(frame, text=label, width=16, anchor="e").pack(side="left", padx=(0, 6))
    var = tk.StringVar(value=default)
    ttk.Combobox(frame, textvariable=var, values=values, width=width - 4).pack(side="left", fill="x", expand=True)
    return frame, var


def make_text(parent, height: int = 10, readonly: bool = False, wrap: str = "word") -> tk.Text:
    text = tk.Text(parent, height=height, wrap=wrap, font=MONO if wrap == "none" else ("Segoe UI", 10))
    if readonly:
        text.configure(state="disabled")
    sb = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    text.pack(side="left", fill="both", expand=True)
    return text


def set_text(text: tk.Text, content: str) -> None:
    text.configure(state="normal")
    text.delete("1.0", "end")
    text.insert("1.0", content)
    text.configure(state="disabled")


def confirm(parent, title: str, message: str) -> bool:
    return messagebox.askyesno(title, message, parent=parent)


def error(parent, title: str, message: str) -> None:
    messagebox.showerror(title, message, parent=parent)


def info(parent, title: str, message: str) -> None:
    messagebox.showinfo(title, message, parent=parent)