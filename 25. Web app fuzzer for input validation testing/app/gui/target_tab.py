"""Tab 1: Target request definition."""

from __future__ import annotations

from tkinter import ttk

from app.gui.widgets import FONT_MONO, FONT_SM, Card, LabeledEntry, add_text
from app.gui.widgets import apply_theme  # noqa: F401 (kept for API parity)
from app.core.injector import json_paths


class TargetTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self._build()

    # ------------------------------------------------------------------ build
    def _build(self):
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(0, weight=1)

        left = Card(self, "Request")
        left.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)

        row0 = ttk.Frame(left.inner, style="TFrame")
        row0.pack(fill="x")
        self.method_var = ttk.Combobox(row0, values=["GET", "POST", "PUT", "PATCH", "DELETE"],
                                       width=9, state="readonly")
        self.method_var.set("GET")
        self.method_var.pack(side="left", padx=(0, 6))
        self.url_var = LabeledEntry(row0, "Target URL (required)", width=60)
        self.url_var.pack(side="left", fill="x", expand=True)

        # Headers / cookies / body
        ttk.Label(left.inner, text="Headers (one per line, `Name: value`)",
                  font=FONT_SM, foreground="#89b4fa").pack(anchor="w", pady=(6, 2))
        self.headers_text = add_text(left.inner, height=5)
        ttk.Label(left.inner, text="Cookies (one per line, `name=value`)",
                  font=FONT_SM, foreground="#89b4fa").pack(anchor="w", pady=(6, 2))
        self.cookies_text = add_text(left.inner, height=2)

        body_row = ttk.Frame(left.inner, style="TFrame")
        body_row.pack(fill="x", pady=(6, 2))
        ttk.Label(body_row, text="Body", font=FONT_SM, foreground="#89b4fa").pack(side="left")
        self.body_type_var = ttk.Combobox(body_row, values=["none", "form", "json", "raw"],
                                          width=8, state="readonly")
        self.body_type_var.set("none")
        self.body_type_var.pack(side="right")
        self.body_text = add_text(left.inner, height=6)
        self.body_text.configure(font=FONT_MONO)

        # Discovered JSON paths helper
        self.json_hint = ttk.Label(left.inner, text="", font=FONT_SM, foreground="#7f849c")
        self.json_hint.pack(fill="x")

        # Right: helper + preview card
        right = Card(self, "")
        right.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)

        ttk.Label(right.inner, text="Injection point hints", font=FONT_SM,
                  foreground="#89b4fa").pack(anchor="w")
        hints = ttk.Label(right.inner, justify="left", font=FONT_SM, foreground="#a6e3a1",
                          text=("• Query params, headers and cookies are auto-discovered.\n"
                                "• Form/JSON bodies are parsed into points.\n"
                                "• Raw body: use {{{{payload}}}} as the injection marker.\n"
                                "• Toggle points in the Payloads tab."))
        hints.pack(anchor="w", pady=6)

        ttk.Label(right.inner, text="Request preview (auto)", font=FONT_SM,
                  foreground="#89b4fa").pack(anchor="w", pady=(10, 2))
        self.preview_text = add_text(right.inner, height=14)

        self.body_type_var.bind("<<ComboboxSelected>>", lambda e: self._update_json_hint())
        self.body_text.bind("<KeyRelease>", lambda e: self._update_json_hint())

        self.update_preview()

    # ------------------------------------------------------------------ state
    def collect(self) -> dict:
        headers = {}
        for line in self.headers_text.get("1.0", "end").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        cookies = {}
        for line in self.cookies_text.get("1.0", "end").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cookies[k.strip()] = v.strip()
        body = self.body_text.get("1.0", "end").rstrip("\n")
        return {
            "target_url": self.url_var.get(),
            "method": self.method_var.get(),
            "headers": headers,
            "cookies": cookies,
            "body": body,
            "body_type": self.body_type_var.get(),
        }

    def apply(self, cfg: dict) -> None:
        self.url_var.set(cfg.get("target_url", ""))
        self.method_var.set(cfg.get("method", "GET"))
        self.headers_text.delete("1.0", "end")
        for k, v in cfg.get("headers", {}).items():
            self.headers_text.insert("end", f"{k}: {v}\n")
        self.cookies_text.delete("1.0", "end")
        for k, v in cfg.get("cookies", {}).items():
            self.cookies_text.insert("end", f"{k}={v}\n")
        self.body_text.delete("1.0", "end")
        self.body_text.insert("1.0", cfg.get("body", ""))
        self.body_type_var.set(cfg.get("body_type", "none"))
        self._update_json_hint()
        self.update_preview()

    def update_preview(self) -> None:
        d = self.collect()
        lines = [f"{d['method']} {d['target_url']}"]
        for k, v in d["headers"].items():
            lines.append(f"{k}: {v}")
        for k, v in d["cookies"].items():
            lines.append(f"Cookie: {k}={v}")
        if d["body_type"] in ("form", "json", "raw") and d["body"]:
            lines.append("")
            lines.append(d["body"])
        self.preview_text.delete("1.0", "end")
        self.preview_text.insert("1.0", "\n".join(lines))
        self.preview_text.configure(state="disabled")

    def _update_json_hint(self) -> None:
        if self.body_type_var.get() == "json":
            paths = json_paths(self.body_text.get("1.0", "end"))
            self.json_hint.configure(text="JSON paths: " + ", ".join(paths) if paths else "No JSON values found")
        else:
            self.json_hint.configure(text="")