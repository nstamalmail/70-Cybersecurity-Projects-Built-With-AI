"""Tab 2 — VLSM Planner: segment requirements in, allocation table out."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from ..app import AppController, UserError
from ..domain.calculator import netmask_from_prefix
from ..domain.models import VlsmPlan
from .theme import restripe_tree
from .widgets import bind_copy

RESULT_COLUMNS = ("name", "required", "prefix", "network", "mask", "usable", "wasted")


class VlsmTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        app: AppController,
        on_import_csv=None,
        on_export_csv=None,
    ) -> None:
        super().__init__(master, padding=8)
        self.app = app
        self._plan: VlsmPlan | None = None
        self._on_import_csv = on_import_csv
        self._on_export_csv = on_export_csv
        self._build()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

        # --- base network + new segment row ------------------------------
        top = ttk.Frame(self)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Base network:").grid(row=0, column=0, sticky="w")
        self.base_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(top, textvariable=self.base_var, width=20).grid(
            row=0, column=1, sticky="w", padx=(0, 24)
        )

        ttk.Label(top, text="New segment:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.seg_name_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.seg_name_var, width=22).grid(
            row=1, column=1, sticky="w", padx=(0, 8), pady=(6, 0)
        )
        ttk.Label(top, text="Hosts:").grid(row=1, column=2, sticky="w", pady=(6, 0))
        self.seg_hosts_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.seg_hosts_var, width=8).grid(
            row=1, column=3, sticky="w", padx=(0, 8), pady=(6, 0)
        )
        ttk.Button(top, text="Add segment", command=self._add_segment).grid(
            row=1, column=4, sticky="w", pady=(6, 0)
        )

        # --- left: requirements ------------------------------------------
        left = ttk.LabelFrame(self, text=" Segment requirements ", padding=8)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        req_columns = ("name", "hosts")
        self.req_tree = ttk.Treeview(left, columns=req_columns, show="headings", height=10)
        self.req_tree.heading("name", text="Segment name")
        self.req_tree.heading("hosts", text="Required hosts")
        self.req_tree.column("name", width=180, anchor="w")
        self.req_tree.column("hosts", width=110, anchor="e")
        self.req_tree.grid(row=0, column=0, sticky="nsew")

        req_scroll = ttk.Scrollbar(left, orient="vertical", command=self.req_tree.yview)
        req_scroll.grid(row=0, column=1, sticky="ns")
        self.req_tree.configure(yscrollcommand=req_scroll.set)

        req_buttons = ttk.Frame(left)
        req_buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(req_buttons, text="Delete selected", command=self._delete_segment).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(req_buttons, text="Clear all", command=self._clear_segments).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(req_buttons, text="Import CSV…", command=self._request_import).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(req_buttons, text="Export CSV…", command=self._request_export).pack(
            side="left"
        )
        ttk.Button(req_buttons, text="Plan VLSM", command=self._run_plan).pack(side="right")

        # --- right: summary ----------------------------------------------
        right = ttk.LabelFrame(self, text=" Plan summary ", padding=8)
        right.grid(row=1, column=1, sticky="nsew")
        self.summary_vars: dict[str, tk.StringVar] = {}
        for key, label in (
            ("required", "Total hosts required"),
            ("allocated", "Addresses allocated"),
            ("wasted", "Hosts wasted"),
            ("efficiency", "Efficiency"),
            ("segments", "Segments"),
        ):
            ttk.Label(right, text=label).pack(anchor="w", pady=(2, 0))
            var = tk.StringVar(value="—")
            ttk.Label(right, textvariable=var, font=("Segoe UI", 10, "bold")).pack(
                anchor="w", pady=(0, 4)
            )
            self.summary_vars[key] = var

        # --- bottom: results ---------------------------------------------
        bottom = ttk.LabelFrame(self, text=" Allocation result ", padding=8)
        bottom.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(0, weight=1)

        self.result_tree = ttk.Treeview(
            bottom, columns=RESULT_COLUMNS, show="headings", height=9
        )
        headings = {
            "name": ("Segment", 20),
            "required": ("Required", 9),
            "prefix": ("Prefix", 8),
            "network": ("Network", 17),
            "mask": ("Netmask", 16),
            "usable": ("Usable", 9),
            "wasted": ("Wasted", 9),
        }
        for col, (title, width) in headings.items():
            self.result_tree.heading(col, text=title)
            self.result_tree.column(col, width=width * 7, anchor="w")
        self.result_tree.column("required", anchor="e")
        self.result_tree.column("usable", anchor="e")
        self.result_tree.column("wasted", anchor="e")
        self.result_tree.grid(row=0, column=0, sticky="nsew")

        result_scroll = ttk.Scrollbar(bottom, orient="vertical",
                                      command=self.result_tree.yview)
        result_scroll.grid(row=0, column=1, sticky="ns")
        self.result_tree.configure(yscrollcommand=result_scroll.set)
        bind_copy(self, self.result_tree, RESULT_COLUMNS)

    # -- segment input actions --------------------------------------------

    def _add_segment(self) -> None:
        name = self.seg_name_var.get().strip()
        hosts = self.seg_hosts_var.get().strip()
        if not name:
            messagebox.showwarning("Add segment", "Enter a segment name.", parent=self)
            return
        try:
            host_count = int(hosts)
        except ValueError:
            messagebox.showwarning(
                "Add segment", f"Host count '{hosts}' is not a whole number.", parent=self
            )
            return
        if not 1 <= host_count <= 2 ** 32 - 2:
            messagebox.showwarning(
                "Add segment", "Host count must be between 1 and 4,294,967,294.", parent=self
            )
            return
        self.req_tree.insert("", "end", values=(name, f"{host_count:,}"))
        restripe_tree(self.req_tree)
        self.seg_name_var.set("")
        self.seg_hosts_var.set("")
        self.seg_name_var.focus_set()  # keep focus for fast entry

    def _delete_segment(self) -> None:
        for item in self.req_tree.selection():
            self.req_tree.delete(item)

    def _clear_segments(self) -> None:
        self.req_tree.delete(*self.req_tree.get_children())

    def rows(self) -> list[tuple[str, str]]:
        """Current requirements as raw (name, hosts_str) rows (hosts de-comma'd)."""
        rows = []
        for item in self.req_tree.get_children():
            name, hosts = self.req_tree.item(item, "values")
            rows.append((str(name), str(hosts).replace(",", "")))
        return rows

    def set_requirements(self, segments: list[tuple[str, int]]) -> None:
        """Replace the requirements table (e.g. after a CSV import)."""
        self.req_tree.delete(*self.req_tree.get_children())
        for name, hosts in segments:
            self.req_tree.insert("", "end", values=(name, f"{hosts:,}"))
        restripe_tree(self.req_tree)
        # Stale results no longer match the new input.
        self.result_tree.delete(*self.result_tree.get_children())
        self._plan = None
        for var in self.summary_vars.values():
            var.set("—")

    # -- CSV callbacks -----------------------------------------------------

    def _request_import(self) -> None:
        if self._on_import_csv:
            self._on_import_csv()

    def _request_export(self) -> None:
        if self._on_export_csv:
            self._on_export_csv()

    # -- planning ---------------------------------------------------------

    def _run_plan(self) -> None:
        try:
            plan = self.app.plan(self.base_var.get(), self.rows())
        except UserError as exc:
            messagebox.showerror("VLSM Plan", str(exc), parent=self)
            return
        self._plan = plan
        self._render(plan)

    def _render(self, plan: VlsmPlan) -> None:
        self.result_tree.delete(*self.result_tree.get_children())
        for seg in plan.segments:
            self.result_tree.insert(
                "", "end",
                values=(
                    seg.name,
                    f"{seg.required_hosts:,}",
                    f"/{seg.prefix}",
                    seg.network,
                    self._mask_for(seg.prefix),
                    f"{seg.usable_hosts:,}",
                    f"{seg.wasted_hosts:,}",
                ),
            )
        self.summary_vars["required"].set(f"{plan.total_required:,}")
        self.summary_vars["allocated"].set(f"{plan.total_allocated:,}")
        self.summary_vars["wasted"].set(f"{plan.total_wasted:,}")
        self.summary_vars["efficiency"].set(f"{plan.efficiency * 100:.2f}%")
        self.summary_vars["segments"].set(str(len(plan.segments)))
        restripe_tree(self.result_tree)

    @staticmethod
    def _mask_for(prefix: int) -> str:
        return netmask_from_prefix(prefix)

    # -- file operations (called from the main window menu) ---------------

    def current_plan(self) -> VlsmPlan | None:
        return self._plan

    def load_plan(self, plan: VlsmPlan) -> None:
        self.base_var.set(plan.base_network)
        self.req_tree.delete(*self.req_tree.get_children())
        for seg in plan.segments:
            self.req_tree.insert(
                "", "end", values=(seg.name, f"{seg.required_hosts:,}")
            )
        self._plan = plan
        self._render(plan)