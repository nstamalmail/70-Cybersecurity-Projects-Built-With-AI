"""HashArmor application shell: Tk root, notebook, statusbar, shared state."""

from __future__ import annotations

import os
import queue
import tkinter as tk
from tkinter import ttk

from core import __version__
from core.session import SessionState
from gui import theme
from gui.tabs.audit_tab import AuditTab
from gui.tabs.crack_tab import CrackTab
from gui.tabs.report_tab import ReportTab
from gui.tabs.settings_tab import SettingsTab

APP_TITLE = "HashArmor — Password Strength Auditor (own hashes only)"


class HashArmorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1080x760")
        self.minsize(900, 620)
        self.configure(bg=theme.BG)

        self.base_dir = os.path.join(os.path.expanduser("~"), "HashArmor")
        os.makedirs(self.base_dir, exist_ok=True)

        self.records = []          # list[HashRecord] — single shared source of truth
        self.fonts = theme.setup(self)
        self._queue: "queue.Queue[tuple]" = queue.Queue()

        self._build()

    # ------------------------------------------------------------- layout

    def _build(self) -> None:
        header = tk.Frame(self, bg=theme.PANEL, height=44)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="⛨ HASHARMOR", bg=theme.PANEL, fg=theme.ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=14)
        tk.Label(header, text=f"v{__version__} · offline · own hashes only",
                 bg=theme.PANEL, fg=theme.FG_DIM).pack(side="left", padx=4)
        ttk.Button(header, text="Run self-test", command=self.run_selftest_quick).pack(
            side="right", padx=10)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self.audit_tab = AuditTab(self.notebook, self)
        self.crack_tab = CrackTab(self.notebook, self)
        self.report_tab = ReportTab(self.notebook, self)
        self.settings_tab = SettingsTab(self.notebook, self)
        self.notebook.add(self.audit_tab, text="  Audit  ")
        self.notebook.add(self.crack_tab, text="  Crack  ")
        self.notebook.add(self.report_tab, text="  Report  ")
        self.notebook.add(self.settings_tab, text="  Settings  ")

        self.status_var = tk.StringVar(value="Ready. Load hashes in the Audit tab to begin.")
        status = ttk.Frame(self)
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.status_var, style="Dim.TLabel").pack(
            side="left", padx=10, pady=3)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --------------------------------------------------------- shared API

    def set_records(self, records, source: str) -> None:
        self.records = records
        self.crack_tab.on_records_changed()
        if source == "audit":
            self.report_tab.preview_reset_hint()

    def refresh_all(self) -> None:
        self.audit_tab.refresh()

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def post(self, fn) -> None:
        """Marshal a callable onto the Tk main loop (thread-safe)."""
        self._queue.put(fn)
        try:
            self.event_generate("<<WorkerPost>>")
        except tk.TclError:
            pass  # app closing

    def run_selftest_quick(self) -> None:
        from core.selftest import run_selftest
        ok, report = run_selftest()
        self.settings_tab.test_out.configure(state="normal")
        self.settings_tab.test_out.delete("1.0", "end")
        self.settings_tab.test_out.insert("1.0", report)
        self.settings_tab.test_out.configure(state="disabled")
        self.notebook.select(self.settings_tab)
        self.set_status("Self-test: " + ("ALL PASS" if ok else "FAILURES"))

    def save_session(self) -> str:
        if not self.records:
            return ""
        st = SessionState(records=self.records)
        st.cracked = {r.digest_hex: r.plaintext for r in self.records if r.plaintext}
        return st.save(self.base_dir)

    def set_base_dir(self, d: str) -> None:
        self.base_dir = d
        os.makedirs(d, exist_ok=True)

    def _drain_queue(self) -> None:
        try:
            while True:
                fn = self._queue.get_nowait()
                fn()
        except queue.Empty:
            pass

    def on_close(self) -> None:
        self.crack_tab.shutdown()
        self.after(150, self.destroy)

    # ------------------------------------------------------------- run

    def run(self) -> None:
        self.bind("<<WorkerPost>>", lambda e: self._drain_queue())
        self.mainloop()


def main() -> None:
    app = HashArmorApp()
    app.run()


if __name__ == "__main__":
    main()
