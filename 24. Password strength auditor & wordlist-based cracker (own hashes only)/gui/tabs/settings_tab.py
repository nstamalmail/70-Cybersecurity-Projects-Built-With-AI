"""Settings tab: base_dir, session management, self-test, about."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import __version__
from core.selftest import run_selftest
from core.session import SessionState
from gui import theme


class SettingsTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app

        box = ttk.Labelframe(self, text="Workspace")
        box.pack(fill="x", padx=12, pady=(12, 6))
        self.base_var = tk.StringVar(value=app.base_dir)
        ttk.Entry(box, textvariable=self.base_var).pack(
            side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(box, text="Choose…", command=self.pick_base).pack(side="left", padx=(0, 8))
        ttk.Button(box, text="Apply", command=self.apply_base).pack(side="left")

        sbox = ttk.Labelframe(self, text="Session (crack progress & results)")
        sbox.pack(fill="x", padx=12, pady=6)
        ttk.Button(sbox, text="Save session", command=self.save_session).pack(
            side="left", padx=8, pady=8)
        ttk.Button(sbox, text="Load session", command=self.load_session).pack(side="left")
        ttk.Button(sbox, text="Delete session", command=self.clear_session).pack(
            side="left", padx=8)
        self.session_var = tk.StringVar(value="")
        ttk.Label(sbox, textvariable=self.session_var, style="Dim.TLabel").pack(
            side="left", padx=12)

        tbox = ttk.Labelframe(self, text="Diagnostics")
        tbox.pack(fill="x", padx=12, pady=6)
        ttk.Button(tbox, text="Run self-test", style="Accent.TButton",
                   command=self.selftest).pack(side="left", padx=8, pady=8)
        self.test_out = tk.Text(tbox, height=12, bg=theme.PANEL2, fg=theme.FG,
                                relief="flat", font=self.app.fonts["mono_small"])
        self.test_out.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        ttk.Label(self, style="Dim.TLabel", justify="left", text=(
            f"HashArmor v{__version__} · offline password strength auditor\n"
            "Runtime: Python standard library only · Reports are self-contained\n"
            "Own hashes only — see the banner on the Crack tab.")).pack(
            anchor="w", padx=12, pady=8)

    def pick_base(self) -> None:
        d = filedialog.askdirectory(title="Choose workspace directory")
        if d:
            self.base_var.set(d)

    def apply_base(self) -> None:
        d = self.base_var.get().strip()
        if not os.path.isdir(d):
            try:
                os.makedirs(d, exist_ok=True)
            except OSError as exc:
                messagebox.showerror("HashArmor", f"Cannot create directory:\n{exc}")
                return
        self.app.set_base_dir(d)
        self.app.set_status(f"Workspace: {d}")

    def save_session(self) -> None:
        p = self.app.save_session()
        self.session_var.set(f"Saved: {p}" if p else "Nothing to save.")
        self.app.set_status("Session saved.")

    def load_session(self) -> None:
        st = SessionState.load(self.app.base_dir)
        if st is None:
            messagebox.showinfo("HashArmor", "No session file found in workspace.")
            return
        self.app.records = st.records
        self.app.refresh_all()
        self.session_var.set(
            f"Loaded {len(st.records)} records · {len(st.cracked)} cracked")
        self.app.set_status("Session loaded.")

    def clear_session(self) -> None:
        from core.session import clear_session_file
        clear_session_file(self.app.base_dir)
        self.session_var.set("")
        self.app.set_status("Session deleted.")

    def selftest(self) -> None:
        ok, report = run_selftest()
        self.test_out.configure(state="normal")
        self.test_out.delete("1.0", "end")
        self.test_out.insert("1.0", report)
        self.test_out.configure(state="disabled")
        self.app.set_status("Self-test: " + ("ALL PASS" if ok else "FAILURES"))
