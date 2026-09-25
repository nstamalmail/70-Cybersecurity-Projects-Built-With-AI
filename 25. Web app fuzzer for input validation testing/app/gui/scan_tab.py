"""Tab 3: Scan control — authorization gate, progress, live log."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from app.gui.widgets import Card, FONT_SM, log_to_text, make_tree


class ScanTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=2)
        self.columnconfigure(1, weight=3)
        self.rowconfigure(0, weight=1)
        self._build()

    def _build(self):
        # --- left: controls
        ctrl = Card(self, "Scan controls")
        ctrl.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)

        self.authorized_var = tk.BooleanVar(value=False)
        self.auth_check = ttk.Checkbutton(
            ctrl.inner,
            text="I confirm I am authorized to test this target (host-locked scan)",
            variable=self.authorized_var,
        )
        self.auth_check.pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(ctrl.inner, style="TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="Threads").pack(side="left")
        self.threads_var = tk.IntVar(value=6)
        ttk.Spinbox(row, from_=1, to=20, textvariable=self.threads_var,
                    width=5).pack(side="left", padx=6)
        ttk.Label(row, text="Delay (ms)").pack(side="left", padx=(12, 0))
        self.delay_var = tk.IntVar(value=50)
        ttk.Spinbox(row, from_=0, to=5000, increment=10,
                    textvariable=self.delay_var, width=6).pack(side="left", padx=6)

        row = ttk.Frame(ctrl.inner, style="TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="Timeout (s)").pack(side="left")
        self.timeout_var = tk.DoubleVar(value=10.0)
        ttk.Spinbox(row, from_=1, to=120, textvariable=self.timeout_var,
                    width=6).pack(side="left", padx=6)
        ttk.Label(row, text="Max requests").pack(side="left", padx=(12, 0))
        self.max_req_var = tk.IntVar(value=1500)
        ttk.Spinbox(row, from_=10, to=100000, increment=50,
                    textvariable=self.max_req_var, width=8).pack(side="left", padx=6)

        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl.inner, text="Follow redirects",
                        variable=self.follow_var).pack(anchor="w", pady=2)
        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl.inner, text="Verify TLS (disable for self-signed)",
                        variable=self.verify_var).pack(anchor="w", pady=2)
        self.tb_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl.inner, text="Detect time-based blind (SLOW on sleepy apps)",
                        variable=self.tb_var).pack(anchor="w", pady=2)

        ttk.Label(ctrl.inner, text="Proxy (http://host:port, optional)",
                  font=FONT_SM, foreground="#7f849c").pack(anchor="w", pady=(8, 2))
        self.proxy_var = tk.StringVar()
        ttk.Entry(ctrl.inner, textvariable=self.proxy_var).pack(fill="x")

        # Buttons
        btns = ttk.Frame(ctrl.inner, style="TFrame")
        btns.pack(fill="x", pady=(12, 0))
        self.scan_btn = ttk.Button(btns, text="▶ Start scan", style="Accent.TButton",
                                   command=self._on_scan_clicked)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.pause_btn = ttk.Button(btns, text="⏸ Pause", command=self._on_pause_clicked)
        self.pause_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(btns, text="⏹ Stop", style="Danger.TButton",
                                   command=self._on_stop_clicked)
        self.stop_btn.pack(side="left", padx=6)

        # Progress
        self.progress = ttk.Progressbar(ctrl.inner, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(14, 4))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(ctrl.inner, textvariable=self.status_var,
                  font=(FONT_SM[0], FONT_SM[1], "bold"), foreground="#a6e3a1").pack(anchor="w")

        stats = ttk.Frame(ctrl.inner, style="TFrame")
        stats.pack(fill="x", pady=(8, 0))
        self.req_var = tk.StringVar(value="Requests: 0")
        self.err_var = tk.StringVar(value="Errors: 0")
        self.fnd_var = tk.StringVar(value="Findings: 0")
        ttk.Label(stats, textvariable=self.req_var).pack(side="left", padx=(0, 14))
        ttk.Label(stats, textvariable=self.err_var).pack(side="left", padx=(0, 14))
        ttk.Label(stats, textvariable=self.fnd_var).pack(side="left")

        # --- right: live log
        log_card = Card(self, "Live log")
        log_card.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        self.log_text = tk.Text(log_card.inner, height=12, wrap="word",
                                font=("Consolas", 9), relief="flat",
                                state="disabled", bg="#16161e", fg="#cdd6f4")
        vsb = ttk.Scrollbar(log_card.inner, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_configure("error", foreground="#f38ba8")
        self.log_text.tag_configure("warn", foreground="#f9e2af")

    # ------------------------------------------------------------- callbacks
    def set_on_scan(self, cb): self._on_scan = cb
    def set_on_pause(self, cb): self._on_pause = cb
    def set_on_stop(self, cb): self._on_stop = cb

    def _on_scan_clicked(self):
        if self._on_scan:
            self._on_scan()

    def _on_pause_clicked(self):
        if self._on_pause:
            self._on_pause()

    def _on_stop_clicked(self):
        if self._on_stop:
            self._on_stop()

    # ---------------------------------------------------------------- helpers
    def log(self, line: str, tag: str = "") -> None:
        log_to_text(self.log_text, line, tag)

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def set_progress(self, done: int, total: int) -> None:
        if total <= 0:
            self.progress["value"] = 0
            return
        self.progress["maximum"] = total
        self.progress["value"] = done

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def set_stats(self, requests: int, errors: int, findings: int) -> None:
        self.req_var.set(f"Requests: {requests}")
        self.err_var.set(f"Errors: {errors}")
        self.fnd_var.set(f"Findings: {findings}")

    def set_running(self, running: bool) -> None:
        """Disable/enable start while a scan runs."""
        state = "disabled" if running else "normal"
        self.scan_btn.configure(state=state)
        self.pause_btn.configure(state=("normal" if running else "disabled"))
        self.stop_btn.configure(state=("normal" if running else "disabled"))
        self.auth_check.configure(state=state)

    # ------------------------------------------------------------------ state
    def collect(self) -> dict:
        return {
            "threads": max(1, self.threads_var.get()),
            "delay_ms": max(0, self.delay_var.get()),
            "timeout": max(1.0, self.timeout_var.get()),
            "max_requests": max(10, self.max_req_var.get()),
            "follow_redirects": self.follow_var.get(),
            "verify_ssl": self.verify_var.get(),
            "time_based": self.tb_var.get(),
            "proxy": self.proxy_var.get().strip(),
            "authorized": self.authorized_var.get(),
        }

    def apply(self, cfg: dict) -> None:
        self.threads_var.set(int(cfg.get("threads", 6)))
        self.delay_var.set(int(cfg.get("delay_ms", 50)))
        self.timeout_var.set(float(cfg.get("timeout", 10.0)))
        self.max_req_var.set(int(cfg.get("max_requests", 1500)))
        self.follow_var.set(cfg.get("follow_redirects", True))
        self.verify_var.set(cfg.get("verify_ssl", True))
        self.tb_var.set(cfg.get("time_based", True))
        self.proxy_var.set(cfg.get("proxy", ""))