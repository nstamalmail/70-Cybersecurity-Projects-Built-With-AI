"""Preview tab — live rendering of the generated artifacts."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..generators import (
    render_decoders_xml,
    render_ossec_snippet,
    render_readme,
    render_rules_csv,
    render_rules_xml,
)
from . import widgets as w

ARTIFACTS = [
    "local_rules.xml",
    "local_decoders.xml",
    "ossec.conf.snippet",
    "README.md",
    "rules.csv",
]


class PreviewTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=8)
        self.app = app

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Artifact:").pack(side="left")
        self.artifact_var = tk.StringVar(value=ARTIFACTS[0])
        ttk.Combobox(bar, textvariable=self.artifact_var, values=ARTIFACTS,
                     state="readonly", width=20).pack(side="left", padx=6)
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left", padx=4)

        self.text = w.make_text(self, readonly=True, wrap="none")
        self.text.pack(fill="both", expand=True)

    def refresh(self) -> None:
        project = self.app.project
        name = self.artifact_var.get()
        try:
            if name == "local_rules.xml":
                content = render_rules_xml(project.chain, project.options)
            elif name == "local_decoders.xml":
                content = render_decoders_xml(project.decoders)
            elif name == "ossec.conf.snippet":
                content = render_ossec_snippet(project.options.decoder_filename,
                                               project.options.rule_filename)
            elif name == "README.md":
                content = render_readme(project.chain, project.options)
            else:
                content = render_rules_csv(project.chain)
        except Exception as exc:  # noqa: BLE001
            content = f"Rendering failed: {exc}"
        w.set_text(self.text, content)