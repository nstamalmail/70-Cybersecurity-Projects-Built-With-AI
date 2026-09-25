"""Generators tab — custom decoders, pack options, validation and export."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, ttk

from ..generators import build_pack_zip, pack_summary, render_decoders_xml, render_rules_xml
from ..models import CustomDecoder
from ..validator import ERROR, WARNING, validate_pack
from . import widgets as w


class GeneratorTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=8)
        self.app = app

        # -- decoders ----------------------------------------------------------
        dec_frame = ttk.LabelFrame(self, text="Custom decoders", padding=6)
        dec_frame.pack(fill="both", expand=True, pady=(0, 6))

        middle = ttk.Panedwindow(dec_frame, orient="horizontal")
        middle.pack(fill="both", expand=True)

        left = ttk.Frame(middle)
        middle.add(left, weight=1)
        self.dec_tree = ttk.Treeview(left, columns=("name",), show="headings", selectmode="browse", height=6)
        self.dec_tree.heading("name", text="Decoder name")
        self.dec_tree.column("name", width=180)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.dec_tree.yview)
        self.dec_tree.configure(yscrollcommand=sb.set)
        self.dec_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.dec_tree.bind("<<TreeviewSelect>>", lambda e: self._load_selected_decoder())

        right = ttk.Frame(middle)
        middle.add(right, weight=2)
        self.dec_name_var = tk.StringVar()
        self.dec_prematch_var = tk.StringVar()
        self.dec_regex_var = tk.StringVar()
        self.dec_order_var = tk.StringVar()
        self.dec_parent_var = tk.StringVar(value="syslog")

        ttk.Label(right, text="Name").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Entry(right, textvariable=self.dec_name_var, width=24).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(right, text="Parent").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Entry(right, textvariable=self.dec_parent_var, width=14).grid(row=0, column=3, sticky="w", padx=4)
        ttk.Label(right, text="Prematch").grid(row=1, column=0, sticky="ne", padx=4)
        ttk.Entry(right, textvariable=self.dec_prematch_var).grid(row=1, column=1, columnspan=3, sticky="ew", padx=4)
        ttk.Label(right, text="Regex").grid(row=2, column=0, sticky="ne", padx=4)
        ttk.Entry(right, textvariable=self.dec_regex_var).grid(row=2, column=1, columnspan=3, sticky="ew", padx=4)
        ttk.Label(right, text="Order").grid(row=3, column=0, sticky="ne", padx=4)
        ttk.Entry(right, textvariable=self.dec_order_var).grid(row=3, column=1, columnspan=3, sticky="ew", padx=4)
        btns = ttk.Frame(right)
        btns.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ttk.Button(btns, text="Add", command=self._add_decoder).pack(side="left", padx=2)
        ttk.Button(btns, text="Update", command=self._update_decoder).pack(side="left", padx=2)
        ttk.Button(btns, text="Delete", command=self._delete_decoder).pack(side="left", padx=2)
        right.columnconfigure(1, weight=1)

        # -- pack options -------------------------------------------------------
        opt_frame = ttk.LabelFrame(self, text="Pack options", padding=6)
        opt_frame.pack(fill="x", pady=(0, 6))
        self.base_id_var = tk.IntVar(value=100000)
        self.group_var = tk.StringVar(value="attack_chain")
        self.rule_file_var = tk.StringVar(value="local_rules.xml")
        self.dec_file_var = tk.StringVar(value="local_decoders.xml")
        self.out_dir_var = tk.StringVar(value=os.path.join(os.getcwd(), "rule_pack_out"))

        ttk.Label(opt_frame, text="Base rule ID").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Spinbox(opt_frame, from_=1, to=900000, textvariable=self.base_id_var, width=10).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(opt_frame, text="Group name").grid(row=0, column=2, sticky="e", padx=4)
        ttk.Entry(opt_frame, textvariable=self.group_var, width=20).grid(row=0, column=3, sticky="w", padx=4)
        ttk.Label(opt_frame, text="Rules file").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Entry(opt_frame, textvariable=self.rule_file_var, width=16).grid(row=1, column=1, sticky="w", padx=4)
        ttk.Label(opt_frame, text="Decoders file").grid(row=1, column=2, sticky="e", padx=4)
        ttk.Entry(opt_frame, textvariable=self.dec_file_var, width=16).grid(row=1, column=3, sticky="w", padx=4)
        ttk.Label(opt_frame, text="Output dir").grid(row=2, column=0, sticky="e", padx=4)
        ttk.Entry(opt_frame, textvariable=self.out_dir_var).grid(row=2, column=1, columnspan=3, sticky="ew", padx=4)
        ttk.Button(opt_frame, text="Browse…", command=self._browse_out).grid(row=2, column=4, padx=4)
        opt_frame.columnconfigure(1, weight=1)

        # -- actions + results ---------------------------------------------------
        act = ttk.Frame(self)
        act.pack(fill="x", pady=(0, 6))
        ttk.Button(act, text="Validate pack", command=self.validate).pack(side="left", padx=4)
        ttk.Button(act, text="Export pack (zip)", command=self.export).pack(side="left", padx=4)
        ttk.Button(act, text="Show generated files", command=self.show_generated).pack(side="left", padx=4)

        self.result_text = w.make_text(self, height=10, readonly=True)
        self.result_text.pack(fill="both", expand=True)

        self.refresh()

    # ------------------------------------------------------------------

    def refresh(self) -> None:
        self._load_options()
        self._reload_decoder_tree()
        summary = pack_summary(self.app.project.chain, self.app.project.decoders)
        self._append_result(
            f"Chain: {summary['steps']} steps, {summary['techniques']} techniques, "
            f"{summary['rules']} rules ({summary['mitre_mapped']} MITRE-mapped), "
            f"{summary['decoders']} custom decoders."
        )

    def _load_options(self) -> None:
        opts = self.app.project.options
        self.base_id_var.set(opts.base_rule_id)
        self.group_var.set(opts.group_name)
        self.rule_file_var.set(opts.rule_filename)
        self.dec_file_var.set(opts.decoder_filename)

    def _save_options(self) -> None:
        opts = self.app.project.options
        opts.base_rule_id = self.base_id_var.get()
        opts.group_name = self.group_var.get().strip() or "attack_chain"
        opts.rule_filename = self.rule_file_var.get().strip() or "local_rules.xml"
        opts.decoder_filename = self.dec_file_var.get().strip() or "local_decoders.xml"

    # ------------------------------------------------------------------
    # Decoders
    # ------------------------------------------------------------------

    def _reload_decoder_tree(self) -> None:
        self.dec_tree.delete(*self.dec_tree.get_children())
        for dec in self.app.project.decoders:
            self.dec_tree.insert("", "end", iid=dec.name or f"dec{id(dec)}",
                                 values=(dec.name,))

    def _selected_decoder(self) -> CustomDecoder | None:
        sel = self.dec_tree.selection()
        if not sel:
            return None
        return next((d for d in self.app.project.decoders if d.name == sel[0]), None)

    def _load_selected_decoder(self) -> None:
        dec = self._selected_decoder()
        if dec is None:
            return
        self.dec_name_var.set(dec.name)
        self.dec_prematch_var.set(dec.prematch)
        self.dec_regex_var.set(dec.regex)
        self.dec_order_var.set(dec.order)
        self.dec_parent_var.set(dec.parent)

    def _add_decoder(self) -> None:
        dec = self._decoder_from_form()
        if not dec.name.strip():
            w.error(self, "Decoder name", "Decoder needs a name.")
            return
        self.app.project.decoders.append(dec)
        self._model_changed(f"Added decoder '{dec.name}'")

    def _update_decoder(self) -> None:
        dec = self._selected_decoder()
        if dec is None:
            w.info(self, "Select a decoder", "Select a decoder in the list to update.")
            return
        updated = self._decoder_from_form()
        idx = self.app.project.decoders.index(dec)
        self.app.project.decoders[idx] = updated
        self._model_changed(f"Updated decoder '{updated.name}'")

    def _delete_decoder(self) -> None:
        dec = self._selected_decoder()
        if dec is None:
            return
        if not w.confirm(self, "Delete decoder", f"Delete decoder '{dec.name}'?"):
            return
        self.app.project.decoders.remove(dec)
        self._model_changed(f"Deleted decoder '{dec.name}'")

    def _decoder_from_form(self) -> CustomDecoder:
        return CustomDecoder(
            name=self.dec_name_var.get().strip(),
            prematch=self.dec_prematch_var.get(),
            regex=self.dec_regex_var.get(),
            order=self.dec_order_var.get(),
            parent=self.dec_parent_var.get().strip() or "syslog",
        )

    # ------------------------------------------------------------------
    # Validation / export
    # ------------------------------------------------------------------

    def validate(self) -> list:
        self._save_options()
        self._set_result("")
        issues = validate_pack(
            self.app.project.chain, self.app.project.decoders, self.app.project.options
        )
        if not issues:
            self._append_result("✓ Validation passed — pack is ready to export.")
        else:
            for issue in sorted(issues, key=lambda i: 0 if i.severity == ERROR else 1):
                self._append_result(issue.display())
            errors = sum(1 for i in issues if i.severity == ERROR)
            self._append_result(f"→ {errors} error(s), {len(issues) - errors} warning(s).")
        return issues

    def export(self) -> None:
        issues = self.validate()
        if any(i.severity == ERROR for i in issues):
            w.error(self, "Validation failed",
                    "Fix the ERROR-level issues before exporting — a broken pack "
                    "would stop all detection on the manager.")
            return
        out_dir = self.out_dir_var.get().strip()
        if not out_dir:
            w.error(self, "Output dir", "Choose an output directory first.")
            return
        try:
            zip_path = build_pack_zip(
                self.app.project.chain,
                self.app.project.decoders,
                self.app.project.options,
                out_dir,
            )
        except OSError as exc:
            w.error(self, "Export failed", f"Could not write pack: {exc}")
            return
        self._append_result(f"✓ Pack exported to:\n   {zip_path}")
        self.app.set_status(f"Exported pack: {zip_path}")

    def show_generated(self) -> None:
        self._save_options()
        self._set_result("")
        try:
            rules = render_rules_xml(self.app.project.chain, self.app.project.options)
            decoders = render_decoders_xml(self.app.project.decoders)
        except Exception as exc:  # noqa: BLE001 — surface anything during rendering
            self._append_result(f"Rendering failed: {exc}")
            return
        self._append_result("=== local_rules.xml (first 40 lines) ===")
        self._append_result("\n".join(rules.splitlines()[:40]))
        self._append_result("")
        self._append_result("=== local_decoders.xml (first 20 lines) ===")
        self._append_result("\n".join(decoders.splitlines()[:20]))

    def _browse_out(self) -> None:
        chosen = filedialog.askdirectory(initialdir=self.out_dir_var.get() or os.getcwd())
        if chosen:
            self.out_dir_var.set(chosen)

    # ------------------------------------------------------------------

    def _append_result(self, text: str) -> None:
        self.result_text.configure(state="normal")
        self.result_text.insert("end", text + "\n")
        self.result_text.configure(state="disabled")

    def _set_result(self, text: str) -> None:
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")

    def _model_changed(self, message: str) -> None:
        self._reload_decoder_tree()
        self.app.on_model_changed(message)