"""Main application window: notebook tabs, menu bar, status bar."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..app import AppController, UserError
from ..util.logging_setup import log_dir_path
from .calculator_tab import CalculatorTab
from .theme import apply_theme
from .vlsm_tab import VlsmTab

APP_NAME = "VLSM Planner"
APP_VERSION = "1.0.0"

PLAN_FILE_TYPES = [("VLSM plan", "*.json"), ("All files", "*.*")]
REPORT_FILE_TYPES = [("Text report", "*.txt"), ("All files", "*.*")]
CSV_FILE_TYPES = [("CSV files", "*.csv"), ("All files", "*.*")]
SVG_FILE_TYPES = [("SVG image", "*.svg"), ("All files", "*.*")]


class MainWindow(tk.Tk):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.title(f"{APP_NAME} v{APP_VERSION} — Custom Subnet Calculator & VLSM Planner")
        self.geometry("1080x720")
        self.minsize(900, 600)

        self._build_menu()
        self._build_body()
        self._build_status_bar()
        self._apply_theme(self.app.get_theme())

    # -- construction -----------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save plan…", command=self._save_plan,
                              accelerator="Ctrl+S")
        file_menu.add_command(label="Load plan…", command=self._load_plan,
                              accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export report…", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Import segments (CSV)…", command=self._import_segments_csv)
        file_menu.add_command(label="Export segments (CSV)…", command=self._export_segments_csv)
        file_menu.add_command(label="Export results (CSV)…", command=self._export_results_csv)
        file_menu.add_command(label="Export diagram (SVG)…", command=self._export_svg)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        self.theme_var = tk.BooleanVar(value=False)
        view_menu.add_checkbutton(
            label="Dark theme", variable=self.theme_var, command=self._toggle_theme
        )
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)
        self.bind_all("<Control-s>", lambda _e: self._save_plan())
        self.bind_all("<Control-o>", lambda _e: self._load_plan())
        self.bind_all("<Control-t>", lambda _e: self._toggle_theme())

    def _build_body(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self.calculator_tab = CalculatorTab(self.notebook, self.app)
        self.vlsm_tab = VlsmTab(
            self.notebook,
            self.app,
            on_import_csv=self._import_segments_csv,
            on_export_csv=self._export_segments_csv,
        )
        self.notebook.add(self.calculator_tab, text="  Subnet Calculator  ")
        self.notebook.add(self.vlsm_tab, text="  VLSM Planner  ")

    def _build_status_bar(self) -> None:
        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w",
                           style="Status.TLabel")
        status.pack(fill="x", side="bottom", padx=8, pady=8)

    # -- theme --------------------------------------------------------------

    def _treeviews(self):
        return (
            self.calculator_tab.division_tree,
            self.vlsm_tab.req_tree,
            self.vlsm_tab.result_tree,
        )

    def _apply_theme(self, mode: str) -> None:
        mode = apply_theme(self, mode, self._treeviews())
        self.theme_var.set(mode == "dark")
        self.current_theme = mode

    def _toggle_theme(self) -> None:
        new_mode = "dark" if not self.theme_var.get() else "light"
        self._apply_theme(new_mode)
        self.app.set_theme(new_mode)
        self.status_var.set(f"Theme switched to {new_mode}.")

    # -- menu actions -----------------------------------------------------

    def _save_plan(self) -> None:
        plan = self.vlsm_tab.current_plan()
        if plan is None:
            messagebox.showinfo(
                APP_NAME, "Run 'Plan VLSM' first so there is a plan to save.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Save VLSM plan", defaultextension=".json",
            filetypes=PLAN_FILE_TYPES,
        )
        if not path:
            return
        try:
            self.app.save_plan(path, plan)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.status_var.set(f"Plan saved to {path}")

    def _load_plan(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Load VLSM plan", filetypes=PLAN_FILE_TYPES
        )
        if not path:
            return
        try:
            plan = self.app.load_plan(path)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.vlsm_tab.load_plan(plan)
        self.status_var.set(f"Loaded plan from {path}")

    def _export_report(self) -> None:
        plan = self.vlsm_tab.current_plan()
        if plan is None:
            messagebox.showinfo(
                APP_NAME, "Run 'Plan VLSM' first so there is a plan to export.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export report", defaultextension=".txt",
            filetypes=REPORT_FILE_TYPES,
        )
        if not path:
            return
        try:
            self.app.export_report(path, plan)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.status_var.set(f"Report exported to {path}")

    # -- CSV actions --------------------------------------------------------

    def _import_segments_csv(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Import segments from CSV", filetypes=CSV_FILE_TYPES
        )
        if not path:
            return
        try:
            segments = self.app.import_segments(path)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.vlsm_tab.set_requirements(segments)
        self.status_var.set(
            f"Imported {len(segments)} segments from {path} — press 'Plan VLSM'."
        )

    def _export_segments_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self, title="Export segments to CSV", defaultextension=".csv",
            filetypes=CSV_FILE_TYPES,
        )
        if not path:
            return
        try:
            self.app.export_segments(path, self.vlsm_tab.rows())
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.status_var.set(f"Segments exported to {path}")

    def _export_results_csv(self) -> None:
        plan = self.vlsm_tab.current_plan()
        if plan is None:
            messagebox.showinfo(
                APP_NAME, "Run 'Plan VLSM' first so there are results to export.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export results to CSV", defaultextension=".csv",
            filetypes=CSV_FILE_TYPES,
        )
        if not path:
            return
        try:
            self.app.export_results_csv(path, plan)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.status_var.set(f"Results exported to {path}")

    def _export_svg(self) -> None:
        plan = self.vlsm_tab.current_plan()
        if plan is None:
            messagebox.showinfo(
                APP_NAME, "Run 'Plan VLSM' first so there is a diagram to export.",
                parent=self,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export diagram (SVG)", defaultextension=".svg",
            filetypes=SVG_FILE_TYPES,
        )
        if not path:
            return
        try:
            self.app.export_svg(path, plan)
        except UserError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return
        self.status_var.set(f"Diagram exported to {path}")

    def _about(self) -> None:
        messagebox.showinfo(
            APP_NAME,
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Custom Subnet Calculator & VLSM Planner\n"
            "Offline, local-only tool. No network access.\n\n"
            "Core: Python 3 · ipaddress (RFC 4632 / RFC 3021)\n"
            f"Logs: {log_dir_path()}\n\n"
            "Shortcuts:\n"
            "  Ctrl+S   save plan · Ctrl+O  load plan\n"
            "  Ctrl+T   toggle theme · Ctrl+C  copy row",
            parent=self,
        )