"""Rules tab — edit DetectionRule objects of the selected technique."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..models import BUILTIN_DECODERS, MITRE_TACTICS, ConditionType, DetectionRule
from . import widgets as w


class RuleTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=8)
        self.app = app
        self._technique_path: tuple[int, int] | None = None

        # -- technique selector ----------------------------------------------
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="Technique:").pack(side="left")
        self.tech_var = tk.StringVar()
        self.tech_combo = ttk.Combobox(top, textvariable=self.tech_var, state="readonly", width=60)
        self.tech_combo.pack(side="left", padx=6, fill="x", expand=True)
        self.tech_combo.bind("<<ComboboxSelected>>", lambda e: self._load_technique_rules())

        # -- table -----------------------------------------------------------
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, pady=(6, 6))
        cols = ("id", "level", "groups", "condition", "pattern", "mitre")
        self.table = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        headings = [("id", "ID"), ("level", "Lvl"), ("groups", "Groups"),
                    ("condition", "Condition"), ("pattern", "Pattern"), ("mitre", "MITRE")]
        for col, title in headings:
            self.table.heading(col, text=title)
        widths = {"id": 70, "level": 45, "groups": 130, "condition": 90, "pattern": 360, "mitre": 90}
        for col, width in widths.items():
            self.table.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)
        self.table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", lambda e: self._load_selected_rule())

        # -- rule form ---------------------------------------------------------
        form = ttk.LabelFrame(self, text="Rule", padding=8)
        form.pack(fill="x")

        self.id_var = tk.IntVar(value=100000)
        self.level_var = tk.IntVar(value=7)
        self.groups_var = tk.StringVar(value="attack_chain")
        self.decoder_var = tk.StringVar(value="syslog")
        self.cond_var = tk.StringVar(value=ConditionType.MATCH.value)
        self.pattern_var = tk.StringVar()
        self.field_var = tk.StringVar()
        self.freq_var = tk.IntVar(value=0)
        self.timeframe_var = tk.IntVar(value=0)
        self.mitre_id_var = tk.StringVar()
        self.mitre_tactic_var = tk.StringVar()
        self.desc_var = tk.StringVar()

        r = 0
        ttk.Label(form, text="ID").grid(row=r, column=0, sticky="e", padx=4)
        ttk.Spinbox(form, from_=1, to=999999, textvariable=self.id_var, width=8).grid(row=r, column=1, sticky="w", padx=4)
        ttk.Label(form, text="Level").grid(row=r, column=2, sticky="e", padx=4)
        ttk.Spinbox(form, from_=0, to=16, textvariable=self.level_var, width=5).grid(row=r, column=3, sticky="w", padx=4)
        ttk.Label(form, text="Decoder").grid(row=r, column=4, sticky="e", padx=4)
        self.decoder_combo = ttk.Combobox(form, textvariable=self.decoder_var, values=BUILTIN_DECODERS, width=16)
        self.decoder_combo.grid(row=r, column=5, sticky="w", padx=4)
        r += 1

        ttk.Label(form, text="Groups").grid(row=r, column=0, sticky="e", padx=4)
        ttk.Entry(form, textvariable=self.groups_var, width=30).grid(row=r, column=1, columnspan=2, sticky="ew", padx=4)
        ttk.Label(form, text="MITRE ID").grid(row=r, column=2, sticky="e", padx=4)
        ttk.Entry(form, textvariable=self.mitre_id_var, width=12).grid(row=r, column=3, sticky="w", padx=4)
        ttk.Label(form, text="Tactic").grid(row=r, column=4, sticky="e", padx=4)
        ttk.Combobox(form, textvariable=self.mitre_tactic_var, values=MITRE_TACTICS, width=20).grid(row=r, column=5, sticky="w", padx=4)
        r += 1

        ttk.Label(form, text="Condition").grid(row=r, column=0, sticky="e", padx=4)
        cond_values = [c.value for c in ConditionType]
        self.cond_combo = ttk.Combobox(form, textvariable=self.cond_var, values=cond_values, state="readonly", width=12)
        self.cond_combo.grid(row=r, column=1, sticky="w", padx=4)
        self.cond_combo.bind("<<ComboboxSelected>>", lambda e: self._toggle_cond_fields())
        ttk.Label(form, text="Field name").grid(row=r, column=2, sticky="e", padx=4)
        ttk.Entry(form, textvariable=self.field_var, width=16).grid(row=r, column=3, sticky="w", padx=4)
        ttk.Label(form, text="Freq").grid(row=r, column=4, sticky="e", padx=4)
        ttk.Spinbox(form, from_=0, to=9999, textvariable=self.freq_var, width=6).grid(row=r, column=5, sticky="w", padx=4)
        ttk.Label(form, text="Timeframe(s)").grid(row=r, column=6, sticky="e", padx=4)
        ttk.Spinbox(form, from_=0, to=86400, textvariable=self.timeframe_var, width=7).grid(row=r, column=7, sticky="w", padx=4)
        r += 1

        ttk.Label(form, text="Pattern").grid(row=r, column=0, sticky="e", padx=4)
        ttk.Entry(form, textvariable=self.pattern_var).grid(row=r, column=1, columnspan=7, sticky="ew", padx=4)
        r += 1

        ttk.Label(form, text="Description").grid(row=r, column=0, sticky="e", padx=4)
        ttk.Entry(form, textvariable=self.desc_var).grid(row=r, column=1, columnspan=7, sticky="ew", padx=4)
        r += 1

        buttons = ttk.Frame(form)
        buttons.grid(row=r, column=0, columnspan=8, sticky="ew", pady=(8, 0))
        ttk.Button(buttons, text="New", command=self._new_rule).pack(side="left", padx=2)
        ttk.Button(buttons, text="Add", command=self._add_rule).pack(side="left", padx=2)
        ttk.Button(buttons, text="Update", command=self._update_rule).pack(side="left", padx=2)
        ttk.Button(buttons, text="Duplicate", command=self._duplicate_rule).pack(side="left", padx=2)
        ttk.Button(buttons, text="Delete", command=self._delete_rule).pack(side="left", padx=2)
        form.columnconfigure(1, weight=1)

        self.refresh()

    # ------------------------------------------------------------------

    def refresh(self) -> None:
        chain = self.app.project.chain
        entries = []
        for si, step in enumerate(chain.steps):
            for ti, tech in enumerate(step.techniques):
                label = f"{si + 1}.{ti + 1}  {tech.technique_id or 'T????'}  {tech.name}"
                entries.append(label)
        self.tech_combo.configure(values=entries)
        if entries and self.tech_var.get() not in entries:
            self.tech_var.set(entries[0])
            self._load_technique_rules()
        else:
            self._load_technique_rules()

    # ------------------------------------------------------------------

    def _technique_index(self) -> tuple[int, int] | None:
        idx = self.tech_combo.current()
        if idx < 0:
            return None
        chain = self.app.project.chain
        flat = [(si, ti) for si, step in enumerate(chain.steps) for ti, _ in enumerate(step.techniques)]
        if idx >= len(flat):
            return None
        return flat[idx]

    def _load_technique_rules(self) -> None:
        self.table.delete(*self.table.get_children())
        pos = self._technique_index()
        self._technique_path = pos
        if pos is None:
            return
        chain = self.app.project.chain
        tech = chain.steps[pos[0]].techniques[pos[1]]
        self.decoder_combo.configure(
            values=BUILTIN_DECODERS + [d.name for d in self.app.project.decoders if d.name])
        for rule in tech.rules:
            self.table.insert("", "end", iid=str(rule.rule_id), values=(
                rule.rule_id, rule.level, rule.groups_str(), rule.condition.value,
                rule.pattern[:60], rule.mitre_id or "-",
            ))

    def _load_selected_rule(self) -> None:
        sel = self.table.selection()
        if not sel or self._technique_path is None:
            return
        chain = self.app.project.chain
        tech = chain.steps[self._technique_path[0]].techniques[self._technique_path[1]]
        rule = next((r for r in tech.rules if str(r.rule_id) == sel[0]), None)
        if rule is None:
            return
        self._fill_form(rule)

    def _fill_form(self, rule: DetectionRule) -> None:
        self.id_var.set(rule.rule_id)
        self.level_var.set(rule.level)
        self.groups_var.set(rule.groups_str())
        self.decoder_var.set(rule.decoder)
        self.cond_var.set(rule.condition.value)
        self.pattern_var.set(rule.pattern)
        self.field_var.set(rule.field_name)
        self.freq_var.set(rule.frequency)
        self.timeframe_var.set(rule.timeframe)
        self.mitre_id_var.set(rule.mitre_id)
        self.mitre_tactic_var.set(rule.mitre_tactic)
        self.desc_var.set(rule.description)
        self._toggle_cond_fields()

    def _rule_from_form(self) -> DetectionRule:
        rule = DetectionRule(
            rule_id=self.id_var.get(),
            level=self.level_var.get(),
            description=self.desc_var.get().strip(),
            decoder=self.decoder_var.get().strip() or "syslog",
            condition=ConditionType(self.cond_var.get()),
            pattern=self.pattern_var.get(),
            field_name=self.field_var.get().strip(),
            frequency=self.freq_var.get(),
            timeframe=self.timeframe_var.get(),
            mitre_id=self.mitre_id_var.get().strip(),
            mitre_tactic=self.mitre_tactic_var.get().strip(),
        )
        rule.set_groups(self.groups_var.get())
        return rule

    def _toggle_cond_fields(self) -> None:
        # Frequency rules reuse the pattern as their base condition; nothing
        # to enable/disable in this UI beyond what the form already offers.
        pass

    # ------------------------------------------------------------------

    def _next_rule_id(self) -> int:
        chain = self.app.project.chain
        used = chain.rule_ids()
        candidate = self.app.project.options.base_rule_id
        while candidate in used:
            candidate += 1
        return candidate

    def _new_rule(self) -> None:
        if self._technique_path is None:
            w.info(self, "No technique", "Select a technique first.")
            return
        self._fill_form(DetectionRule(
            rule_id=self._next_rule_id(),
            level=7,
            groups=["attack_chain"],
            description="",
            decoder="syslog",
        ))

    def _add_rule(self) -> None:
        if self._technique_path is None:
            w.info(self, "No technique", "Select a technique first.")
            return
        rule = self._rule_from_form()
        chain = self.app.project.chain
        tech = chain.steps[self._technique_path[0]].techniques[self._technique_path[1]]
        if any(r.rule_id == rule.rule_id for r in tech.rules):
            w.error(self, "Duplicate ID", f"Rule ID {rule.rule_id} already exists in this technique.")
            return
        tech.rules.append(rule)
        self._model_changed(f"Added rule {rule.rule_id}")

    def _update_rule(self) -> None:
        if self._technique_path is None:
            return
        sel = self.table.selection()
        if not sel:
            w.info(self, "Select a rule", "Select a rule in the table to update.")
            return
        rule = self._rule_from_form()
        chain = self.app.project.chain
        tech = chain.steps[self._technique_path[0]].techniques[self._technique_path[1]]
        for i, existing in enumerate(tech.rules):
            if str(existing.rule_id) == sel[0]:
                tech.rules[i] = rule
                break
        self._model_changed(f"Updated rule {rule.rule_id}")

    def _duplicate_rule(self) -> None:
        if self._technique_path is None:
            return
        sel = self.table.selection()
        if not sel:
            return
        chain = self.app.project.chain
        tech = chain.steps[self._technique_path[0]].techniques[self._technique_path[1]]
        src = next((r for r in tech.rules if str(r.rule_id) == sel[0]), None)
        if src is None:
            return
        import copy
        dup = copy.deepcopy(src)
        dup.rule_id = self._next_rule_id()
        tech.rules.append(dup)
        self._model_changed(f"Duplicated rule {src.rule_id} -> {dup.rule_id}")

    def _delete_rule(self) -> None:
        if self._technique_path is None:
            return
        sel = self.table.selection()
        if not sel:
            return
        if not w.confirm(self, "Delete rule", f"Delete rule {sel[0]}?"):
            return
        chain = self.app.project.chain
        tech = chain.steps[self._technique_path[0]].techniques[self._technique_path[1]]
        tech.rules = [r for r in tech.rules if str(r.rule_id) != sel[0]]
        self._model_changed(f"Deleted rule {sel[0]}")

    # ------------------------------------------------------------------

    def _model_changed(self, message: str) -> None:
        self._load_technique_rules()
        self.app.on_model_changed(message)