"""Main window — owns the model and wires the tabs together."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..generators import pack_summary
from ..models import RulePackProject
from ..persistence import load_project, save_project
from ..presets import load_preset, list_presets
from . import widgets as w
from .chain_tab import ChainTab
from .deploy_tab import DeployTab
from .generator_tab import GeneratorTab
from .preview_tab import PreviewTab
from .rule_tab import RuleTab

APP_TITLE = "Wazuh/OSSEC Rule Pack Builder"


class MainWindow:
    def __init__(self, root: tk.Tk, project: RulePackProject | None = None):
        self.root = root
        self.project = project if project is not None else load_preset(list_presets()[0])
        self.current_path: str | None = None

        root.title(APP_TITLE)
        root.geometry("1180x760")
        root.minsize(980, 620)

        self._build_menu()
        self._build_statusbar()

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        self.chain_tab = ChainTab(self.notebook, self)
        self.rule_tab = RuleTab(self.notebook, self)
        self.generator_tab = GeneratorTab(self.notebook, self)
        self.preview_tab = PreviewTab(self.notebook, self)
        self.deploy_tab = DeployTab(self.notebook, self)

        self.notebook.add(self.chain_tab, text=" Attack Chain ")
        self.notebook.add(self.rule_tab, text=" Rules ")
        self.notebook.add(self.generator_tab, text=" Generators & Export ")
        self.notebook.add(self.preview_tab, text=" Preview ")
        self.notebook.add(self.deploy_tab, text=" Deploy ")

        self.set_status("Ready.")

    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New blank chain", command=self._new_blank)
        preset_menu = tk.Menu(filemenu, tearoff=0)
        for name in list_presets():
            preset_menu.add_command(label=name, command=lambda n=name: self._load_preset(n))
        filemenu.add_cascade(label="Load preset chain", menu=preset_menu)
        filemenu.add_separator()
        filemenu.add_command(label="Open project…", command=self.open_project)
        filemenu.add_command(label="Save project", command=self.save_project)
        filemenu.add_command(label="Save project as…", command=self.save_project_as)
        filemenu.add_separator()
        filemenu.add_command(label="Export pack (zip)", command=self._export_pack)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.root.config(menu=menubar)

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar(value="")
        bar = ttk.Frame(self.root, relief="sunken", padding=(6, 2))
        bar.pack(side="bottom", fill="x")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.stats_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.stats_var).pack(side="right")

    # ------------------------------------------------------------------

    def on_model_changed(self, message: str) -> None:
        """Called by tabs after any model mutation — refresh everything."""
        self.rule_tab.refresh()
        self.generator_tab.refresh()
        self.preview_tab.refresh()
        self.deploy_tab.refresh()
        self.set_status(message)

    def set_status(self, message: str) -> None:
        self.status_var.set(message)
        summary = pack_summary(self.project.chain, self.project.decoders)
        self.stats_var.set(
            f"{summary['steps']} steps · {summary['techniques']} techniques · "
            f"{summary['rules']} rules · {summary['decoders']} decoders"
        )

    def load_project(self, project: RulePackProject) -> None:
        """Swap in a whole new project (preset / blank / opened file)."""
        self.project = project
        self.current_path = None
        for tab in (self.chain_tab, self.rule_tab, self.generator_tab,
                    self.preview_tab, self.deploy_tab):
            tab.refresh()
        self.set_status(f"Loaded: {project.chain.name}")

    # ------------------------------------------------------------------
    # Menu actions
    # ------------------------------------------------------------------

    def _new_blank(self) -> None:
        self.load_project(RulePackProject())
        self.set_status("New blank chain")

    def _load_preset(self, name: str) -> None:
        if not w.confirm(self.root, "Load preset",
                         f"Replace the current chain with preset '{name}'?"):
            return
        self.load_project(load_preset(name))
        self.set_status(f"Loaded preset: {name}")

    def open_project(self) -> None:
        path = filedialog.askopenfilename(
            title="Open project",
            filetypes=[("Rule pack project", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            project = load_project(path)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Open failed", str(exc), parent=self.root)
            return
        self.project = project
        self.current_path = path
        self.load_project(project)
        self.set_status(f"Opened: {path}")

    def save_project(self) -> None:
        if self.current_path is None:
            self.save_project_as()
            return
        self._write_project(self.current_path)

    def save_project_as(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save project",
            defaultextension=".json",
            initialfile=f"{self._safe_name()}.json",
            filetypes=[("Rule pack project", "*.json")],
        )
        if not path:
            return
        self._write_project(path)

    def _write_project(self, path: str) -> None:
        try:
            save_project(self.project, path)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc), parent=self.root)
            return
        self.current_path = path
        self.set_status(f"Saved: {path}")

    def _safe_name(self) -> str:
        keep = [c if c.isalnum() or c in "-_" else "_" for c in self.project.chain.name.strip().lower()]
        return "".join(keep)[:40] or "project"

    def _export_pack(self) -> None:
        self.notebook.select(self.generator_tab)
        self.generator_tab.export()

    def _about(self) -> None:
        messagebox.showinfo(
            APP_TITLE,
            "Custom Wazuh/OSSEC detection rule pack builder.\n\n"
            "Design an attack chain, map techniques to detection rules, "
            "validate and export a deployable rule pack.\n\n"
            "Targets: Wazuh 4.x / OSSEC 3.x managers.",
            parent=self.root,
        )