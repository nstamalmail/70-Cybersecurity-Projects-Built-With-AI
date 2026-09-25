"""Attack Chain tab — edit the Chain -> Step -> Technique hierarchy."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..models import MITRE_TACTICS, AttackStep, AttackTechnique
from . import widgets as w


class ChainTab(ttk.Frame):
    """Left: tree of steps/techniques. Right: forms + preset loader."""

    def __init__(self, master, app):
        super().__init__(master, padding=8)
        self.app = app  # MainWindow controller
        self._map: dict[str, tuple[int, int | None]] = {}

        # -- chain metadata ------------------------------------------------
        meta = ttk.LabelFrame(self, text="Chain", padding=6)
        meta.pack(fill="x")
        self.chain_name_var = tk.StringVar()
        self.chain_desc_var = tk.StringVar()
        ttk.Label(meta, text="Name").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Entry(meta, textvariable=self.chain_name_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(meta, text="Description").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Entry(meta, textvariable=self.chain_desc_var).grid(row=1, column=1, sticky="ew", padx=4)
        meta.columnconfigure(1, weight=1)

        ttk.Button(meta, text="Apply metadata", command=self._apply_metadata).grid(
            row=0, column=2, rowspan=2, padx=8)

        # -- preset loader -------------------------------------------------
        loadbar = ttk.Frame(self)
        loadbar.pack(fill="x", pady=(8, 4))
        ttk.Label(loadbar, text="Load preset chain:").pack(side="left")
        self.preset_var = tk.StringVar()
        from ..presets import list_presets
        ttk.Combobox(loadbar, textvariable=self.preset_var, values=list_presets(),
                     state="readonly", width=28).pack(side="left", padx=6)
        ttk.Button(loadbar, text="Load", command=self._load_preset).pack(side="left", padx=2)
        ttk.Button(loadbar, text="New blank chain", command=self._new_blank).pack(side="left", padx=2)

        # -- body: tree + forms ---------------------------------------------
        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, pady=(4, 0))

        left = ttk.Frame(body)
        body.add(left, weight=3)
        cols = ("kind",)
        self.tree = ttk.Treeview(left, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Attack chain")
        self.tree.heading("kind", text="Kind")
        self.tree.column("#0", width=320)
        self.tree.column("kind", width=120, anchor="center")
        ttk.Button(left, text="Refresh tree", command=self.refresh).pack(fill="x", pady=(4, 0))
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = ttk.Frame(body)
        body.add(right, weight=2)

        # -- step form -------------------------------------------------------
        self.step_frame = ttk.LabelFrame(right, text="Step (phase)", padding=6)
        self.step_frame.pack(fill="x", pady=(0, 6))
        self.step_name_var = tk.StringVar()
        self.step_desc_var = tk.StringVar()
        ttk.Label(self.step_frame, text="Name").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Entry(self.step_frame, textvariable=self.step_name_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(self.step_frame, text="Description").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Entry(self.step_frame, textvariable=self.step_desc_var).grid(row=1, column=1, sticky="ew", padx=4)
        btn_row = ttk.Frame(self.step_frame)
        btn_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(btn_row, text="Add step", command=self._add_step).pack(side="left", padx=2)
        ttk.Button(btn_row, text="Update step", command=self._update_step).pack(side="left", padx=2)
        ttk.Button(btn_row, text="Delete step", command=self._delete_step).pack(side="left", padx=2)
        self.step_frame.columnconfigure(1, weight=1)

        # -- technique form ---------------------------------------------------
        self.tech_frame = ttk.LabelFrame(right, text="Technique (ATT&CK)", padding=6)
        self.tech_frame.pack(fill="x")
        self.tech_id_var = tk.StringVar()
        self.tech_name_var = tk.StringVar()
        self.tech_tactic_var = tk.StringVar()
        self.tech_desc_var = tk.StringVar()
        ttk.Label(self.tech_frame, text="Technique ID").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Entry(self.tech_frame, textvariable=self.tech_id_var, width=12).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(self.tech_frame, text="Name").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Entry(self.tech_frame, textvariable=self.tech_name_var).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Label(self.tech_frame, text="Tactic").grid(row=2, column=0, sticky="e", padx=4)
        ttk.Combobox(self.tech_frame, textvariable=self.tech_tactic_var, values=MITRE_TACTICS,
                     width=24).grid(row=2, column=1, sticky="w", padx=4)
        ttk.Label(self.tech_frame, text="Description").grid(row=3, column=0, sticky="e", padx=4)
        ttk.Entry(self.tech_frame, textvariable=self.tech_desc_var).grid(row=3, column=1, sticky="ew", padx=4)
        tbtn = ttk.Frame(self.tech_frame)
        tbtn.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(tbtn, text="Add technique", command=self._add_technique).pack(side="left", padx=2)
        ttk.Button(tbtn, text="Update technique", command=self._update_technique).pack(side="left", padx=2)
        ttk.Button(tbtn, text="Delete technique", command=self._delete_technique).pack(side="left", padx=2)
        self.tech_frame.columnconfigure(1, weight=1)

        self.refresh()

    # ------------------------------------------------------------------
    # Tree rendering / selection
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._map.clear()
        chain = self.app.project.chain
        self.chain_name_var.set(chain.name)
        self.chain_desc_var.set(chain.description)
        for si, step in enumerate(chain.steps):
            step_iid = f"s{si}"
            self._map[step_iid] = (si, None)
            self.tree.insert("", "end", iid=step_iid, text=step.name or "(unnamed step)",
                             values=("step",))
            for ti, tech in enumerate(step.techniques):
                tid = f"s{si}t{ti}"
                self._map[tid] = (si, ti)
                label = tech.name or "(unnamed technique)"
                if tech.technique_id:
                    label = f"{tech.technique_id}  {label}"
                self.tree.insert(step_iid, "end", iid=tid, text=label,
                                 values=(f"{len(tech.rules)} rules",))

    def _selected(self) -> tuple[tuple[int, int | None], str]:
        sel = self.tree.selection()
        if not sel:
            return (None, None), ""
        return self._map[sel[0]], sel[0]

    def _on_select(self, _event=None) -> None:
        (pos, iid) = self._selected()
        if pos is None:
            return
        si, ti = pos
        chain = self.app.project.chain
        if ti is None:
            step = chain.steps[si]
            self.step_name_var.set(step.name)
            self.step_desc_var.set(step.description)
        else:
            tech = chain.steps[si].techniques[ti]
            self.tech_id_var.set(tech.technique_id)
            self.tech_name_var.set(tech.name)
            self.tech_tactic_var.set(tech.tactic)
            self.tech_desc_var.set(tech.description)

    # ------------------------------------------------------------------
    # Step actions
    # ------------------------------------------------------------------

    def _add_step(self) -> None:
        name = self.step_name_var.get().strip() or "New Step"
        self.app.project.chain.steps.append(AttackStep(name=name, description=self.step_desc_var.get().strip()))
        self._model_changed("Added step")

    def _update_step(self) -> None:
        (pos, _) = self._selected()
        if pos is None or pos[1] is not None:
            return
        step = self.app.project.chain.steps[pos[0]]
        step.name = self.step_name_var.get().strip() or step.name
        step.description = self.step_desc_var.get().strip()
        self._model_changed("Updated step")

    def _delete_step(self) -> None:
        (pos, _) = self._selected()
        if pos is None or pos[1] is not None:
            return
        if not w.confirm(self, "Delete step", "Delete this step and all its techniques/rules?"):
            return
        del self.app.project.chain.steps[pos[0]]
        self._model_changed("Deleted step")

    # ------------------------------------------------------------------
    # Technique actions
    # ------------------------------------------------------------------

    def _add_technique(self) -> None:
        (pos, _) = self._selected()
        if pos is None:
            return
        step = self.app.project.chain.steps[pos[0]]
        step.techniques.append(AttackTechnique(
            technique_id=self.tech_id_var.get().strip(),
            name=self.tech_name_var.get().strip() or "New Technique",
            tactic=self.tech_tactic_var.get().strip(),
            description=self.tech_desc_var.get().strip(),
        ))
        self._model_changed("Added technique")

    def _update_technique(self) -> None:
        (pos, _) = self._selected()
        if pos is None or pos[1] is None:
            return
        tech = self.app.project.chain.steps[pos[0]].techniques[pos[1]]
        tech.technique_id = self.tech_id_var.get().strip()
        tech.name = self.tech_name_var.get().strip() or tech.name
        tech.tactic = self.tech_tactic_var.get().strip()
        tech.description = self.tech_desc_var.get().strip()
        self._model_changed("Updated technique")

    def _delete_technique(self) -> None:
        (pos, _) = self._selected()
        if pos is None or pos[1] is None:
            return
        if not w.confirm(self, "Delete technique", "Delete this technique and its rules?"):
            return
        del self.app.project.chain.steps[pos[0]].techniques[pos[1]]
        self._model_changed("Deleted technique")

    # ------------------------------------------------------------------
    # Presets / blank
    # ------------------------------------------------------------------

    def _load_preset(self) -> None:
        name = self.preset_var.get()
        if not name:
            return
        from ..presets import load_preset
        self.app.load_project(load_preset(name))
        self._model_changed(f"Loaded preset: {name}")

    def _new_blank(self) -> None:
        from ..models import AttackChain, RulePackProject
        self.app.load_project(RulePackProject(chain=AttackChain(name="Untitled Attack Chain")))
        self._model_changed("New blank chain")

    def _apply_metadata(self) -> None:
        chain = self.app.project.chain
        chain.name = self.chain_name_var.get().strip() or chain.name
        chain.description = self.chain_desc_var.get().strip()
        self._model_changed("Updated chain metadata")

    # ------------------------------------------------------------------

    def _model_changed(self, message: str) -> None:
        self.refresh()
        self.app.on_model_changed(message)