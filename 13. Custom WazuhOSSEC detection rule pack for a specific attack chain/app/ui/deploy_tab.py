"""Deploy tab — step-by-step deployment instructions with copy support."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..generators import render_readme
from . import widgets as w


class DeployTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=8)
        self.app = app

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(bar, text="Copy to clipboard", command=self._copy).pack(side="left", padx=6)
        ttk.Label(bar, text="(also ships inside the exported pack as README.md)").pack(side="left")

        self.text = w.make_text(self, readonly=True)
        self.text.pack(fill="both", expand=True)

    def refresh(self) -> None:
        project = self.app.project
        w.set_text(self.text, render_readme(project.chain, project.options))

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(render_readme(self.app.project.chain, self.app.project.options))
        self.app.set_status("Deployment README copied to clipboard")