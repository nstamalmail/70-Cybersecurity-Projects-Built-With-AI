"""Tab 2: Payloads & injection points configuration."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app.core.models import PAYLOAD_CATEGORIES
from app.core.payloads import category_label
from app.gui.widgets import Card, FONT_SM, add_text, make_tree

KIND_LABELS = {
    "query": "Query param",
    "path": "Path",
    "header": "Header",
    "cookie": "Cookie",
    "body_form": "Form body",
    "body_json": "JSON body",
    "body_raw": "Raw body",
}


class PayloadsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")

        self.category_vars = {}
        self.encoding_vars = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- left: categories
        cat_card = Card(self, "Payload categories")
        cat_card.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        for cat in PAYLOAD_CATEGORIES[:-1]:  # 'custom' handled via text area
            var = tk.BooleanVar(value=True)
            self.category_vars[cat] = var
            ttk.Checkbutton(cat_card.inner, text=category_label(cat),
                            variable=var).pack(anchor="w", padx=6, pady=2)
        ttk.Label(cat_card.inner,
                  text="Custom payloads are enabled when the "
                       "text area on the right is non-empty.",
                  font=FONT_SM, foreground="#7f849c",
                  wraplength=260).pack(anchor="w", padx=6, pady=(10, 0))

        # --- middle: injection points
        ip_card = Card(self, "Injection points (auto-discovered; toggle as needed)")
        ip_card.grid(row=0, column=1, sticky="nsew", padx=(5, 5), pady=10)

        list_row = ttk.Frame(ip_card.inner, style="TFrame")
        list_row.pack(fill="both", expand=True)
        self.ip_tree = make_tree(list_row, ("enabled", "kind", "name", "value"),
                                 ("On", "Kind", "Name", "Value"),
                                 (40, 110, 160, 200), selectmode="extended")
        self.ip_items = {}

        btn_row = ttk.Frame(ip_card.inner, style="TFrame")
        btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(btn_row, text="Enable sel.", command=lambda: self._toggle(True)).pack(side="left", padx=(0, 4))
        ttk.Button(btn_row, text="Disable sel.", command=lambda: self._toggle(False)).pack(side="left", padx=4)

        # --- right: encodings + custom
        enc_card = Card(self, "Encodings")
        enc_card.grid(row=0, column=2, sticky="nsew", padx=(5, 10), pady=10)
        enc_labels = {
            "none": "None",
            "url": "URL-encoded",
            "double_url": "Double URL-encoded",
            "html_entities": "HTML entities",
            "base64": "Base64",
            "unicode": "%u unicode",
        }
        for enc, label in enc_labels.items():
            var = tk.BooleanVar(value=(enc in ("none", "url")))
            self.encoding_vars[enc] = var
            ttk.Checkbutton(enc_card.inner, text=label, variable=var).pack(anchor="w", padx=6, pady=2)
        ttk.Label(enc_card.inner, text="More encodings = more requests.",
                  font=FONT_SM, foreground="#7f849c").pack(anchor="w", padx=6, pady=(6, 0))

        ttk.Label(enc_card.inner, text="Custom payloads (one per line)",
                  font=FONT_SM, foreground="#89b4fa").pack(anchor="w", pady=(12, 2))
        self.custom_text = add_text(enc_card.inner, height=8)

        load_row = ttk.Frame(enc_card.inner, style="TFrame")
        load_row.pack(fill="x", pady=(4, 0))
        ttk.Button(load_row, text="⬆ Load payloads from file…",
                   command=self._load_payloads_file).pack(side="left")
        ttk.Button(load_row, text="✕ Clear payloads",
                   command=lambda: self._set_custom_text([])).pack(side="left", padx=4)
        ttk.Label(enc_card.inner,
                  text="Tip: samples/sample_payloads.txt is a ready-made list.",
                  font=FONT_SM, foreground="#7f849c", wraplength=240).pack(anchor="w", pady=(4, 0))

    def _load_payloads_file(self) -> None:
        """Append custom payloads from a user-selected text file (one per line)."""
        from app.config import SAMPLES_DIR
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Load payloads from file", initialdir=initial,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = [ln.strip() for ln in fh.read().splitlines()]
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("WebFuzzer", f"Could not read payload file: {exc}")
            return
        payloads = [ln for ln in lines if ln and not ln.startswith("#")]
        if not payloads:
            messagebox.showwarning("WebFuzzer", "No payload lines found in that file.")
            return
        existing = [l.strip() for l in self.custom_text.get("1.0", "end").splitlines() if l.strip()]
        merged = existing + [p for p in payloads if p not in existing]
        self._set_custom_text(merged)
        messagebox.showinfo("WebFuzzer", f"Loaded {len(payloads)} payload(s) from\n{path}")

    def _set_custom_text(self, payloads: list) -> None:
        self.custom_text.configure(state="normal")
        self.custom_text.delete("1.0", "end")
        for p in payloads:
            self.custom_text.insert("end", p + "\n")

    # ------------------------------------------------------------------ points
    def set_points(self, points: list) -> None:
        # Preserve the user's enabled/disabled choice for points that persist.
        prev = {ip.key(): ip.enabled for ip in self.get_all_points()}
        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)
        self.ip_items.clear()
        for ip in points:
            if ip.key() in prev:
                ip.enabled = prev[ip.key()]
            item = self.ip_tree.insert("", "end",
                                       values=("✓" if ip.enabled else "✗",
                                               KIND_LABELS.get(ip.kind, ip.kind),
                                               ip.name, ip.value[:80]))
            self.ip_items[item] = ip

    def _toggle(self, enabled: bool) -> None:
        for item in self.ip_tree.selection():
            ip = self.ip_items.get(item)
            if ip:
                ip.enabled = enabled
                self.ip_tree.set(item, "enabled", "✓" if enabled else "✗")

    def get_enabled_points(self) -> list:
        return [ip for ip in self.ip_items.values() if ip.enabled]

    def get_all_points(self) -> list:
        return list(self.ip_items.values())

    # ------------------------------------------------------------------ state
    def collect(self) -> dict:
        categories = [c for c, v in self.category_vars.items() if v.get()]
        encodings = [e for e, v in self.encoding_vars.items() if v.get()]
        custom = [l.strip() for l in self.custom_text.get("1.0", "end").splitlines() if l.strip()]
        return {"categories": categories, "encodings": encodings, "custom_payloads": custom}

    def apply(self, cfg: dict) -> None:
        for cat, var in self.category_vars.items():
            var.set(cat in cfg.get("categories", []))
        for enc, var in self.encoding_vars.items():
            var.set(enc in cfg.get("encodings", ["none", "url"]))
        self._set_custom_text(list(cfg.get("custom_payloads", [])))

    def validate(self) -> bool:
        has_custom = bool(self.custom_text.get("1.0", "end").strip())
        if not any(v.get() for v in self.category_vars.values()) and not has_custom:
            messagebox.showwarning("WebFuzzer", "Select at least one payload category "
                                                "or provide custom payloads.")
            return False
        if not any(v.get() for v in self.encoding_vars.values()):
            messagebox.showwarning("WebFuzzer", "Select at least one encoding.")
            return False
        return True