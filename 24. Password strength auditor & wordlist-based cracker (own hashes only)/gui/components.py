"""Reusable GUI components: smooth progress bar, legal banner."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from . import theme


class SmoothProgress(tk.Canvas):
    """Canvas-based progress bar with a % label (smoother than ttk's)."""

    def __init__(self, master, height: int = 18, **kw):
        super().__init__(master, height=height, highlightthickness=0,
                         bg=theme.PANEL2, **kw)
        self._frac = 0.0
        self._shown = 0.0
        self.bind("<Configure>", lambda e: self._redraw())
        self._animate()

    def set_fraction(self, frac: float) -> None:
        self._frac = max(0.0, min(1.0, frac))

    def _animate(self) -> None:
        # Ease toward the target for a smooth feel.
        self._shown += (self._frac - self._shown) * 0.25
        if abs(self._frac - self._shown) < 0.001:
            self._shown = self._frac
        self._redraw()
        self.after(33, self._animate)

    def _redraw(self) -> None:
        self.delete("all")
        w = max(self.winfo_width(), 10)
        h = max(self.winfo_height(), 10)
        self.create_rectangle(0, 0, w, h, fill=theme.PANEL2, outline=theme.BORDER)
        frac = max(0.0, min(1.0, self._shown))
        if frac > 0:
            self.create_rectangle(1, 1, 1 + (w - 2) * frac, h - 1,
                                  fill=theme.ACCENT, outline="")
        pct = f"{frac * 100:5.1f}%"
        self.create_text(w // 2, h // 2, text=pct,
                         fill=theme.FG if frac > 0.35 else theme.FG_DIM,
                         font=theme_fonts(self))


def theme_fonts(widget: tk.Widget):
    try:
        return widget._hasharmor_font  # type: ignore[attr-defined]
    except AttributeError:
        f = ("Segoe UI", 9)
        widget._hasharmor_font = f  # type: ignore[attr-defined]
        return f


class LegalBanner(tk.Frame):
    """Red-bordered authorization banner + consent checkbox."""

    def __init__(self, master, var: tk.BooleanVar):
        super().__init__(master, bg="#2b1016", highlightthickness=2,
                         highlightbackground=theme.CRIT)
        self.columnconfigure(0, weight=1)
        head = tk.Label(
            self, fg=theme.CRIT, bg="#2b1016", justify="left",
            font=("Segoe UI", 10, "bold"),
            text="AUTHORIZED USE ONLY — OWN HASHES")
        head.grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))
        body = tk.Label(
            self, fg=theme.FG, bg="#2b1016", justify="left", wraplength=640,
            text="Only load and attack password hashes that YOU created or systems "
                 "you own / are contractually authorized to test. Attacking hashes "
                 "without authorization is illegal (e.g. CFAA, Computer Misuse Act). "
                 "You accept full legal responsibility for the hashes you load.")
        body.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 4))
        chk = tk.Checkbutton(
            self, variable=var, bg="#2b1016", fg=theme.FG, selectcolor="#1a1f26",
            activebackground="#2b1016", activeforeground=theme.FG,
            highlightthickness=0, bd=0,
            text="I confirm the hashes above are mine / I am authorized to test them")
        chk.grid(row=2, column=0, sticky="w", padx=10, pady=(0, 8))
