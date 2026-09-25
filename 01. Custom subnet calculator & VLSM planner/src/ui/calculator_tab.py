"""Tab 1 — Subnet Calculator: single subnet details + equal division."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from ..app import AppController, UserError
from ..domain.calculator import DIVISION_PARTS
from ..domain.models import SubnetInfo
from .theme import restripe_tree
from .widgets import bind_copy, grid_of_labels

RESULT_FIELDS: tuple[tuple[str, str], ...] = (
    ("network", "Network"),
    ("netmask", "Netmask"),
    ("wildcard", "Wildcard mask"),
    ("broadcast", "Broadcast"),
    ("first", "First host"),
    ("last", "Last host"),
    ("usable", "Usable hosts"),
    ("total", "Total addresses"),
)


class CalculatorTab(ttk.Frame):
    def __init__(self, master: tk.Misc, app: AppController) -> None:
        super().__init__(master, padding=8)
        self.app = app
        self._last_info: SubnetInfo | None = None
        self._build()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        # --- input row ---------------------------------------------------
        input_frame = ttk.LabelFrame(self, text=" Input ", padding=8)
        input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        input_frame.columnconfigure(1, weight=1)
        input_frame.columnconfigure(3, weight=1)

        ttk.Label(input_frame, text="IP address:").grid(row=0, column=0, sticky="w")
        self.ip_var = tk.StringVar(value="192.168.1.25")
        ttk.Entry(input_frame, textvariable=self.ip_var, width=20).grid(
            row=0, column=1, sticky="w", padx=(0, 16)
        )

        ttk.Label(input_frame, text="Prefix (CIDR):").grid(row=0, column=2, sticky="w")
        self.prefix_var = tk.StringVar(value="24")
        ttk.Entry(input_frame, textvariable=self.prefix_var, width=8).grid(
            row=0, column=3, sticky="w", padx=(0, 16)
        )

        ttk.Label(input_frame, text="Netmask:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.mask_var = tk.StringVar(value="")
        ttk.Entry(input_frame, textvariable=self.mask_var, width=20).grid(
            row=1, column=1, sticky="w", pady=(6, 0)
        )

        ttk.Button(input_frame, text="Calculate", command=self._calculate).grid(
            row=1, column=2, columnspan=2, sticky="w", padx=(0, 16), pady=(6, 0)
        )
        ttk.Label(
            input_frame,
            text="Enter prefix OR netmask — the other is derived automatically.",
            style="Muted.TLabel",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(4, 0))

        # --- results -----------------------------------------------------
        results_frame = ttk.LabelFrame(self, text=" Subnet details ", padding=8)
        results_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.result_vars = grid_of_labels(results_frame, RESULT_FIELDS, value_width=34)

        # --- binary ------------------------------------------------------
        binary_frame = ttk.LabelFrame(self, text=" Binary ", padding=8)
        binary_frame.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(binary_frame, text="Network:").grid(row=0, column=0, sticky="w")
        self.bin_net_var = tk.StringVar()
        ttk.Entry(binary_frame, textvariable=self.bin_net_var, state="readonly",
                  width=42).grid(row=0, column=1, sticky="w")
        ttk.Label(binary_frame, text="Mask:   ").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.bin_mask_var = tk.StringVar()
        ttk.Entry(binary_frame, textvariable=self.bin_mask_var, state="readonly",
                  width=42).grid(row=1, column=1, sticky="w", pady=(4, 0))

        # --- equal division ---------------------------------------------
        division_frame = ttk.LabelFrame(self, text=" Equal division into subnets ", padding=8)
        division_frame.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        division_frame.columnconfigure(1, weight=1)

        ttk.Label(division_frame, text="Network:").grid(row=0, column=0, sticky="w")
        self.div_net_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(division_frame, textvariable=self.div_net_var, width=28).grid(
            row=0, column=1, sticky="w", padx=(0, 16)
        )
        ttk.Label(division_frame, text="Split into:").grid(row=0, column=2, sticky="w")
        self.parts_var = tk.StringVar(value="4")
        ttk.Combobox(
            division_frame, textvariable=self.parts_var, width=6, state="readonly",
            values=[str(p) for p in DIVISION_PARTS],
        ).grid(row=0, column=3, sticky="w", padx=(0, 16))
        ttk.Button(division_frame, text="Divide", command=self._divide).grid(
            row=0, column=4, sticky="w"
        )

        # --- division results -------------------------------------------
        table_frame = ttk.Frame(self)
        table_frame.grid(row=4, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("network", "prefix", "netmask", "first", "last", "usable")
        self.division_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=7
        )
        headings = {
            "network": ("Subnet", 18),
            "prefix": ("Prefix", 8),
            "netmask": ("Netmask", 16),
            "first": ("First host", 16),
            "last": ("Last host", 16),
            "usable": ("Usable hosts", 12),
        }
        for col, (title, width) in headings.items():
            self.division_tree.heading(col, text=title)
            self.division_tree.column(col, width=width * 7, anchor="w", stretch=True)
        self.division_tree.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(table_frame, orient="vertical",
                               command=self.division_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.division_tree.configure(yscrollcommand=scroll.set)
        bind_copy(self, self.division_tree, columns)

    # -- actions ----------------------------------------------------------

    def _calculate(self) -> None:
        try:
            info = self.app.calculate(self.ip_var.get(), self.prefix_var.get()
                                      or self.mask_var.get())
        except UserError as exc:
            messagebox.showerror("Subnet Calculator", str(exc), parent=self)
            return

        values = {
            "network": info.network,
            "netmask": info.netmask,
            "wildcard": info.wildcard,
            "broadcast": info.broadcast_address,
            "first": info.first_host,
            "last": info.last_host,
            "usable": f"{info.usable_hosts:,}",
            "total": f"{info.total_hosts:,}",
        }
        for key, var in self.result_vars.items():
            var.set(values.get(key, ""))
        self.bin_net_var.set(info.binary_network)
        self.bin_mask_var.set(info.binary_mask)

        # Sync prefix <-> mask entries and prefill the division network.
        self.prefix_var.set(str(info.prefix))
        self.mask_var.set(info.netmask)
        self.div_net_var.set(info.network)
        self._last_info = info

    def _divide(self) -> None:
        try:
            parts = int(self.parts_var.get())
            results = self.app.divide(self.div_net_var.get(), parts)
        except (UserError, ValueError) as exc:
            messagebox.showerror("Equal Division", str(exc), parent=self)
            return

        self.division_tree.delete(*self.division_tree.get_children())
        for info in results:
            self.division_tree.insert(
                "", "end",
                values=(info.network, f"/{info.prefix}", info.netmask,
                        info.first_host, info.last_host, f"{info.usable_hosts:,}"),
            )
        restripe_tree(self.division_tree)