"""Crack tab: attack config, legal gate, start/stop, live progress and results."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.attack import AttackEngine, MASK_PRESETS
from core.session import AttackConfig
from core.wordlists import builtin_wordlists
from gui import theme
from gui.components import LegalBanner, SmoothProgress


class CrackTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app
        self.engine: AttackEngine | None = None
        self.worker: threading.Thread | None = None
        self._ui_lock = threading.Lock()

        self.authorized = tk.BooleanVar(value=False)
        self.mode = tk.StringVar(value="dictionary")
        self.wordlist_var = tk.StringVar()
        self.wordlist2_var = tk.StringVar()
        self.rules_var = tk.StringVar()
        self.mask_var = tk.StringVar(value="?d?d?d?d")

        self._build()

    # ------------------------------------------------------------------ UI

    def _build(self) -> None:
        pad = {"padx": 12, "pady": 4}

        LegalBanner(self, self.authorized).pack(fill="x", padx=12, pady=(12, 4))
        self.authorized.trace_add("write", lambda *_: self._update_gate())

        row = ttk.Frame(self)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Attack mode:", style="Dim.TLabel").pack(side="left")
        for text, val in (("Wordlist", "dictionary"), ("Wordlist + Rules", "rules"),
                          ("Mask / brute force", "mask"), ("Combinator", "combinator")):
            ttk.Radiobutton(row, text=text, value=val, variable=self.mode,
                            command=self._mode_changed).pack(side="left", padx=(10, 0))

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, **pad)

        # --- wordlist pickers ---
        self.wl_frame = ttk.Labelframe(body, text="Wordlist")
        self.wl_frame.pack(fill="x")
        self.wl_combo = ttk.Combobox(self.wl_frame, textvariable=self.wordlist_var,
                                     state="readonly")
        self.wl_combo.pack(side="left", fill="x", expand=True, padx=8, pady=6)
        ttk.Button(self.wl_frame, text="Browse…",
                   command=self._pick_wordlist).pack(side="left", padx=(0, 8), pady=6)

        self.wl2_frame = ttk.Labelframe(body, text="Second wordlist (combinator)")
        self.wl2_combo = ttk.Combobox(self.wl2_frame, textvariable=self.wordlist2_var,
                                      state="readonly")
        self.wl2_combo.pack(side="left", fill="x", expand=True, padx=8, pady=6)
        ttk.Button(self.wl2_frame, text="Browse…",
                   command=self._pick_wordlist2).pack(side="left", padx=(0, 8), pady=6)

        # --- rules picker ---
        self.rules_frame = ttk.Labelframe(body, text="Rule file (hashcat notation)")
        self.rules_combo = ttk.Combobox(self.rules_frame, textvariable=self.rules_var,
                                        values=["assets/wordlists/best64.rule"],
                                        state="readonly")
        self.rules_combo.current(0)
        self.rules_combo.pack(side="left", fill="x", expand=True, padx=8, pady=6)
        ttk.Button(self.rules_frame, text="Browse…",
                   command=self._pick_rules).pack(side="left", padx=(0, 8), pady=6)

        # --- mask editor ---
        self.mask_math_var = tk.StringVar(value="")
        self.mask_frame = ttk.Labelframe(body, text="Mask (?l lower ?u upper ?d digit ?s symbol ?a all)")
        mask_row = ttk.Frame(self.mask_frame)
        mask_row.pack(fill="x", padx=8, pady=6)
        ttk.Entry(mask_row, textvariable=self.mask_var, width=28).pack(side="left")
        ttk.Label(mask_row, textvariable=self.mask_math_var, style="Dim.TLabel").pack(
            side="left", padx=10)
        presets = ttk.Combobox(mask_row, values=list(MASK_PRESETS.keys()),
                               state="readonly", width=24)
        presets.pack(side="right")
        presets.bind("<<ComboboxSelected>>",
                     lambda e: self.mask_var.set(
                         MASK_PRESETS.get(presets.get(), self.mask_var.get())))

        self._reload_builtins()
        self._mode_changed()

        # --- controls ---
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", **pad)
        self.start_btn = ttk.Button(ctrl, text="▶ Start attack", style="Accent.TButton",
                                    command=self.start, state="disabled")
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctrl, text="■ Stop", style="Danger.TButton",
                                   command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.stat_var = tk.StringVar(value="Idle.")
        ttk.Label(ctrl, textvariable=self.stat_var, style="Dim.TLabel").pack(
            side="left", padx=12)

        self.progress = SmoothProgress(ctrl, height=16)
        self.progress.pack(side="left", fill="x", expand=True, padx=(12, 0))

        # --- live log ---
        self.log = tk.Text(self, height=10, bg=theme.PANEL2, fg=theme.FG,
                           insertbackground=theme.FG, relief="flat",
                           font=self.app.fonts["mono_small"])
        self.log.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self.log.insert("end", "Found credentials will appear here.\n")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------ helpers

    def _reload_builtins(self) -> None:
        items = [label for label, _ in builtin_wordlists()]
        paths = [p for _, p in builtin_wordlists()]
        self.wl_combo.configure(values=items)
        self.wl2_combo.configure(values=items)
        if items:
            self.wl_combo.current(0)
            self.wl2_combo.current(0)
            self._builtin_paths = dict(zip(items, paths))
        else:
            self._builtin_paths = {}

    def _wordlist_path(self, var: tk.StringVar) -> str:
        v = var.get()
        return self._builtin_paths.get(v, v)

    def _pick_wordlist(self) -> None:
        p = filedialog.askopenfilename(title="Choose wordlist",
                                       filetypes=[("Wordlists", "*.txt *.dic *.lst"), ("All", "*.*")])
        if p:
            self.wordlist_var.set(p)

    def _pick_wordlist2(self) -> None:
        p = filedialog.askopenfilename(title="Choose second wordlist")
        if p:
            self.wordlist2_var.set(p)

    def _pick_rules(self) -> None:
        p = filedialog.askopenfilename(title="Choose rule file",
                                       filetypes=[("Rule files", "*.rule *.txt"), ("All", "*.*")])
        if p:
            self.rules_var.set(p)

    def _mode_changed(self) -> None:
        m = self.mode.get()
        if m == "dictionary":
            self.wl_frame.pack(fill="x", pady=2)
            self.rules_frame.pack_forget()
            self.mask_frame.pack_forget()
            self.wl2_frame.pack_forget()
        elif m == "rules":
            self.wl_frame.pack(fill="x", pady=2)
            self.rules_frame.pack(fill="x", pady=2)
            self.mask_frame.pack_forget()
            self.wl2_frame.pack_forget()
        elif m == "mask":
            self.wl_frame.pack_forget()
            self.rules_frame.pack_forget()
            self.mask_frame.pack(fill="x", pady=2)
            self.wl2_frame.pack_forget()
        else:  # combinator
            self.wl_frame.pack(fill="x", pady=2)
            self.wl2_frame.pack(fill="x", pady=2)
            self.rules_frame.pack_forget()
            self.mask_frame.pack_forget()
        self._update_mask_math()
        self._update_gate()

    def _update_mask_math(self) -> None:
        if not hasattr(self, "mask_math_var"):
            return
        tmp = AttackEngine([], AttackConfig(mode="mask", mask=self.mask_var.get()))
        n = tmp.mask_count(self.mask_var.get())
        if n == 0:
            self.mask_math_var.set("Invalid mask")
        elif n > 1_000_000:
            self.mask_math_var.set(f"= {n:,} candidates — EXCEEDS 1M cap")
        else:
            self.mask_math_var.set(f"= {n:,} candidates")

    def _build_config(self) -> AttackConfig | None:
        m = self.mode.get()
        cfg = AttackConfig(mode=m)
        if m in ("dictionary", "rules", "combinator"):
            cfg.wordlist = self._wordlist_path(self.wordlist_var)
            if not cfg.wordlist:
                return None
        if m == "rules":
            cfg.rules_file = self.rules_var.get()
            if not cfg.rules_file:
                return None
        if m == "mask":
            cfg.mask = self.mask_var.get()
            eng = AttackEngine([], cfg)
            n = eng.mask_count(cfg.mask)
            if n == 0 or n > cfg.max_candidates:
                return None
        if m == "combinator":
            cfg.wordlist2 = self._wordlist_path(self.wordlist2_var)
            if not cfg.wordlist2:
                return None
        return cfg

    def _update_gate(self, *_args) -> None:
        if not hasattr(self, "start_btn"):
            return
        ready = (self.authorized.get()
                 and bool(self.app.records)
                 and self._build_config() is not None)
        self.start_btn.configure(state="normal" if ready else "disabled")

    def on_records_changed(self) -> None:
        self._update_gate()

    # ------------------------------------------------------------ run

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        cfg = self._build_config()
        if cfg is None:
            messagebox.showwarning("HashArmor", "Attack configuration incomplete.")
            return
        if not self.authorized.get():
            messagebox.showwarning("HashArmor", "Acknowledge the authorization banner first.")
            return

        self.engine = AttackEngine(self.app.records, cfg, authorized=True)
        if cfg.mode == "mask":
            n = self.engine.mask_count(cfg.mask)
            if not messagebox.askokcancel(
                    "HashArmor", f"Mask will generate {n:,} candidates. Proceed?"):
                return
        self.engine.total_estimate = self.engine.mask_count(cfg.mask)

        self.log_configure("normal")
        self.log.delete("1.0", "end")
        self.log_configure("disabled")
        self.stop_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
        self.app.set_status(f"Running {cfg.mode} attack…")

        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def stop(self) -> None:
        if self.engine:
            self.engine.stop_event.set()

    def _run(self) -> None:
        eng = self.engine

        def tick(snap: dict) -> None:
            self.app.post(lambda: self._on_tick(snap, eng))

        try:
            result = eng.run(progress_cb=tick)
        except Exception as exc:
            self.app.post(lambda: self._on_error(str(exc)))
            return
        self.app.post(lambda: self._on_done(result))

    def _on_tick(self, snap: dict, eng: AttackEngine) -> None:
        with self._ui_lock:
            total = snap.get("total") or 0
            frac = snap["candidates"] / total if total else 0.0
            self.progress.set_fraction(frac)
            eta = snap.get("eta") or 0
            self.stat_var.set(
                f"{snap['candidates']:,} tried · {snap['found']} found · "
                f"{snap['rate']:,.0f} c/s · ETA {eta:,.0f}s")
            self._flush_finds(eng)

    def _flush_finds(self, eng: AttackEngine) -> None:
        new_items = []
        for rec in eng.records:
            if rec.plaintext and not getattr(rec, "_logged", False):
                rec._logged = True  # type: ignore[attr-defined]
                new_items.append(rec)
        if new_items:
            self.log_configure("normal")
            for rec in new_items:
                self.log.insert("end",
                                f"[+] {rec.display_name()} ({rec.algo}) = {rec.plaintext}\n")
            self.log_configure("disabled")
            self.app.set_records(list(eng.records), source="crack")
            self.app.refresh_all()

    def _on_error(self, msg: str) -> None:
        self.stop_btn.configure(state="disabled")
        self._update_gate()
        messagebox.showerror("HashArmor", f"Attack failed:\n{msg}")

    def _on_done(self, result: dict) -> None:
        self.progress.set_fraction(1.0 if result["finished"] else 0.0)
        self.stop_btn.configure(state="disabled")
        self._update_gate()
        self._flush_finds(self.engine)
        status = ("finished" if result["finished"]
                  else "stopped" if result["stopped"] else "error")
        self.stat_var.set(
            f"{status.capitalize()} — {result['candidates']:,} candidates, "
            f"{result['found']} cracked.")
        self.app.set_status(f"Attack {status}. {result['found']} credential(s) found.")
        if result.get("error"):
            messagebox.showerror("HashArmor", f"Engine error: {result['error']}")

    def log_configure(self, state: str) -> None:
        self.log.configure(state=state)

    def shutdown(self) -> None:
        if self.engine:
            self.engine.stop_event.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=2.0)
