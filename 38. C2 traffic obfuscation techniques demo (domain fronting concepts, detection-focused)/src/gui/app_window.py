"""Main workbench window: left-rail controls + notebook of detection views.

Threading model: the engine runs in a worker thread; results come back through
a queue.Queue polled by ``after()``. Tk is only ever touched from the main thread.
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk

from src import __version__
from src.safety import assert_safe
from src.gui import views
from src.gui.panels import draw_pie, draw_timeline
from src.simulator.scenario import SCENARIOS
from src.detections import DEFAULT_THRESHOLDS, RULE_METADATA


class Workbench(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"C2 Detection Workbench — offline synthetic demo v{__version__}")
        self.geometry("1180x760")
        self.minsize(980, 620)

        self.result = None
        self._worker = None
        self._queue: queue.Queue = queue.Queue()

        self._build_menu()
        self._build_layout()
        self._set_status("Ready — pick a scenario and click Run.", ready=True)

    # ------------------------------------------------------------------ menu
    def _build_menu(self):
        m = tk.Menu(self)
        filem = tk.Menu(m, tearoff=0)
        filem.add_command(label="Run", command=self._on_run)
        filem.add_separator()
        filem.add_command(label="Open artifacts folder", command=self._open_artifacts)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.destroy)
        m.add_cascade(label="File", menu=filem)
        helpm = tk.Menu(m, tearoff=0)
        helpm.add_command(label="Safety contract", command=self._show_safety)
        helpm.add_command(label="About", command=lambda: self.notebook.select(7))
        m.add_cascade(label="Help", menu=helpm)
        self.config(menu=m)

    # ---------------------------------------------------------------- layout
    def _build_layout(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        rail = ttk.Frame(self, padding=10)
        rail.grid(row=0, column=0, sticky="ns")
        nb = ttk.Notebook(self)
        nb.grid(row=0, column=1, sticky="nsew", padx=(0, 6), pady=6)
        self.notebook = nb

        # --- left rail ---
        ttk.Label(rail, text="Scenario", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.scenario_var = tk.StringVar(value="c2_domain_fronting")
        for name, cfg in SCENARIOS.items():
            ttk.Radiobutton(rail, text=cfg.label, value=name,
                            variable=self.scenario_var).pack(anchor="w")
        ttk.Separator(rail).pack(fill="x", pady=8)
        ttk.Label(rail, text="Seed").pack(anchor="w")
        self.seed_var = tk.StringVar(value="1337")
        ttk.Spinbox(rail, from_=0, to=999999, textvariable=self.seed_var, width=10).pack(anchor="w")
        self.decoys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rail, text="Include decoys", variable=self.decoys_var).pack(anchor="w")
        ttk.Separator(rail).pack(fill="x", pady=8)
        self.run_btn = ttk.Button(rail, text="▶ Run", command=self._on_run)
        self.run_btn.pack(fill="x")
        self.progress = ttk.Progressbar(rail, mode="indeterminate", length=140)
        self.progress.pack(fill="x", pady=6)
        ttk.Separator(rail).pack(fill="x", pady=8)
        ttk.Button(rail, text="Open artifacts", command=self._open_artifacts).pack(fill="x")

        # --- notebook ---
        self.views = []
        for View in (views.DashboardView, views.FlowsView, views.TLSView, views.BeaconView,
                     views.DetectionsView, views.PcapView, views.ZtnView, views.AboutView):
            v = View(nb)
            self.views.append(v)
            nb.add(v.frame, text=View.title if hasattr(View, "title") else "Tab")

    # ----------------------------------------------------------------- run
    def _on_run(self):
        if self._worker and self._worker.is_alive():
            return
        try:
            seed = int(self.seed_var.get())
        except ValueError:
            seed = 1337
        scenario = self.scenario_var.get()
        include_decoys = self.decoys_var.get()
        self.run_btn.configure(state="disabled")
        self.progress.start(12)
        self._set_status(f"Simulating '{scenario}' (seed {seed})…")
        self._worker = threading.Thread(
            target=self._work, args=(scenario, seed, include_decoys), daemon=True)
        self._worker.start()
        self.after(100, self._poll)

    def _work(self, scenario, seed, include_decoys):
        try:
            from src.pipeline import run_pipeline
            res = run_pipeline(scenario, seed, include_decoys)
            self._queue.put(("ok", res))
        except Exception as exc:  # surfaced in the GUI, never crashes Tk
            self._queue.put(("err", exc))

    def _poll(self):
        try:
            kind, payload = self._queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll)
            return
        self.progress.stop()
        self.run_btn.configure(state="normal")
        if kind == "err":
            self._set_status(f"Error: {payload}", ready=True)
            return
        self.result = payload
        for v in self.views:
            if hasattr(v, "update_result"):
                v.update_result(payload)
        c = payload.verdict_counts
        self._set_status(
            f"Done: {len(payload.flows)} flows · {c['malicious']} malicious · "
            f"{c['suspicious']} suspicious · {len(payload.findings)} findings", ready=True)

    def _set_status(self, text: str, ready: bool = False):
        for w in self.grid_slaves(row=1, column=1):
            w.destroy()
        bar = ttk.Frame(self, padding=(6, 4))
        bar.grid(row=1, column=1, sticky="ew")
        color = "#2e7d32" if ready else "#ef6c00"
        dot = "●" if ready else "○"
        tk.Label(bar, text=f"{dot}", fg=color).pack(side="left")
        tk.Label(bar, text=" " + text).pack(side="left")

    def _open_artifacts(self):
        import subprocess
        from pathlib import Path
        p = Path("artifacts").resolve()
        p.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["explorer", str(p)])
        except OSError:
            pass

    def _show_safety(self):
        from src.gui.views import AboutView
        self.notebook.select(7)

    def run(self):
        self.mainloop()


def launch():
    assert_safe()
    Workbench().run()


if __name__ == "__main__":
    launch()
