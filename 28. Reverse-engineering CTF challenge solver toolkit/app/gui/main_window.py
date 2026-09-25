"""RECT main window: controller, toolbar, tabs, event loop wiring.

Threading contract: workers push events onto queue.Queue; the main thread
polls via root.after() and applies them to widgets.
"""

from __future__ import annotations

import json
import os
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_base_dir, get_data_dir
from app.core.engine import AnalysisEngine, run_operation_blocking
from app.core.models import AnalysisRecord, Challenge, now_iso
from app.gui.tabs import (AnalysisTab, CryptoTab, HistoryTab, OpsTab,
                          SettingsTab, WorkspaceTab, WriteupTab)
from app.gui.widgets import apply_theme
from app.storage.database import Database
from app.utils.settings import Settings
from app.utils.state import StateStore

POLL_MS = 80


class RectApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.db = Database()
        self.settings = Settings()
        self.state = StateStore()
        self.events: "queue.Queue" = queue.Queue()
        self.engine: AnalysisEngine | None = None
        self.challenge: Challenge | None = None
        self.challenge_id: int | None = None
        self.binary_data: bytes = b""
        self.current_strings: list = []

        apply_theme(root)
        root.title(f"{APP_NAME} — Reverse-Engineering CTF Solver Toolkit "
                   f"v{__version__}")
        root.geometry("1280x840")
        root.minsize(1080, 720)

        self._build_toolbar()
        self._build_tabs()
        self._wire_callbacks()

        self._log(f"{APP_NAME} started. One challenge = one case: "
                  "metadata + binary + ops log + writeup.")
        self.state.log_memory("GUI session started")
        self._write_state()
        self.settings_tab.refresh_memory(self.state.read_memory())

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    # ------------------------------------------------------------------ build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="🧩 " + APP_NAME, font=("Segoe UI", 15, "bold"),
                  foreground="#89b4fa").pack(side="left")
        ttk.Label(bar, text=" One challenge, one workspace",
                  foreground="#7f849c").pack(side="left", padx=(8, 0))

        ttk.Button(bar, text="💾 Save case",
                   command=self._save_case).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="🆕 New case",
                   command=self._new_case).pack(side="right", padx=(6, 0))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.workspace_tab = WorkspaceTab(self.notebook)
        self.analysis_tab = AnalysisTab(self.notebook)
        self.crypto_tab = CryptoTab(self.notebook)
        self.ops_tab = OpsTab(self.notebook)
        self.writeup_tab = WriteupTab(self.notebook)
        self.history_tab = HistoryTab(self.notebook, db=self.db)
        self.settings_tab = SettingsTab(self.notebook)

        self.notebook.add(self.workspace_tab, text="  1. Workspace  ")
        self.notebook.add(self.analysis_tab, text="  2. Analysis  ")
        self.notebook.add(self.crypto_tab, text="  3. Crypto helpers  ")
        self.notebook.add(self.ops_tab, text="  4. Ops & console  ")
        self.notebook.add(self.writeup_tab, text="  5. Writeup  ")
        self.notebook.add(self.history_tab, text="  6. History  ")
        self.notebook.add(self.settings_tab, text="  7. Settings  ")

        base = get_base_dir()
        self.settings_tab.set_paths({
            "Base dir": base,
            "state.md": os.path.join(base, "state.md"),
            "memory.md": os.path.join(base, "memory.md"),
            "settings.json": os.path.join(get_data_dir(), "settings.json"),
            "Database": self.db.path,
            "Samples": SAMPLES_DIR,
        })

    def _wire_callbacks(self) -> None:
        self.workspace_tab.on_load_binary = self._load_binary
        self.workspace_tab.on_import_sample = self._import_sample_file
        self.crypto_tab.on_run = self._run_crypto_op
        self.writeup_tab.on_export = self._export_writeup
        self.writeup_tab.on_save_flag = self._save_case
        self.history_tab.on_load_challenge = self._open_challenge
        self.history_tab.on_delete_challenge = self._delete_challenge

    # ------------------------------------------------------------- case mgmt
    def _collect_challenge(self) -> Challenge:
        w = self.workspace_tab.collect()
        wr = self.writeup_tab.collect()
        ch = self.challenge or Challenge(name=w["challenge_name"] or "untitled")
        ch.name = w["challenge_name"] or ch.name
        ch.category = w["category"]
        ch.event = w["event"]
        ch.description = w["description"]
        ch.flag_format = w["flag_format"]
        ch.binary_path = w["binary_path"]
        ch.flag = wr["flag"]
        ch.solved = wr["solved"]
        ch.notes_md = wr["notes_md"]
        return ch

    def _save_case(self) -> None:
        ch = self._collect_challenge()
        if not ch.name:
            messagebox.showwarning(APP_NAME, "Give the challenge a name first.")
            return
        if self.challenge_id is None:
            self.challenge_id = self.db.create_challenge(ch)
            ch.id = self.challenge_id
            self.state.log_memory(f"challenge created: {ch.name} (#{self.challenge_id})")
        else:
            ch.id = self.challenge_id
            self.db.update_challenge(ch)
            self.state.log_memory(f"challenge updated: {ch.name} (#{self.challenge_id})")
        self.challenge = ch
        self.history_tab.refresh()
        self._log(f"Case saved: {ch.name} (#{self.challenge_id})")

    def _new_case(self) -> None:
        self.challenge = None
        self.challenge_id = None
        self.binary_data = b""
        self.workspace_tab.apply({})
        self.writeup_tab.apply({})
        self.analysis_tab.set_info_text("No binary loaded.")
        self.ops_tab.log("— new case —", "warn")

    def _open_challenge(self, cid: int) -> None:
        row = self.db.get_challenge(cid)
        if not row:
            return
        self.challenge_id = cid
        self.challenge = Challenge(
            name=row["name"], category=row["category"], event=row["event"] or "",
            description=row["description"] or "",
            flag_format=row["flag_format"] or "flag{",
            binary_path=row["binary_path"] or "", solved=bool(row["solved"]),
            flag=row["flag"] or "", notes_md=row["notes_md"] or "")
        self.workspace_tab.apply({
            "challenge_name": row["name"], "category": row["category"],
            "event": row["event"] or "", "description": row["description"] or "",
            "flag_format": row["flag_format"] or "flag{",
            "binary_path": row["binary_path"] or "",
        })
        self.writeup_tab.apply({"flag": row["flag"] or "",
                                "solved": bool(row["solved"]),
                                "notes_md": row["notes_md"] or ""})
        ops = self.db.list_operations(cid)
        self.ops_tab.ops_tree.delete(*self.ops_tab.ops_tree.get_children())
        for rec in ops:
            self.ops_tab.add_record(rec)
        if row["binary_path"] and os.path.exists(row["binary_path"]):
            self._load_binary()
        self.notebook.select(self.workspace_tab)
        self._log(f"Opened challenge #{cid} ({row['name']}, {len(ops)} ops).")

    def _delete_challenge(self, cid: int) -> None:
        self.db.delete_challenge(cid)
        if self.challenge_id == cid:
            self._new_case()
        self.history_tab.refresh()

    def _import_sample_file(self, path: str) -> None:
        self.workspace_tab.binary_var.set(path)
        w = self.workspace_tab.collect()
        if not w["challenge_name"]:
            self.workspace_tab.name_var.set(os.path.basename(path))
            self.workspace_tab.category_var.set("rev")
        self.state.log_memory(f"sample challenge file selected: "
                              f"{os.path.basename(path)}")
        self._load_binary()

    # ------------------------------------------------------------- analysis
    def _load_binary(self) -> None:
        path = self.workspace_tab.binary_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning(APP_NAME, f"File not found:\n{path}")
            return
        try:
            with open(path, "rb") as fh:
                self.binary_data = fh.read(8_000_000)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read file: {exc}")
            return
        self._run_engine_op("load")

    def _run_engine_op(self, op: str) -> None:
        if self.engine and self.engine.is_alive():
            messagebox.showwarning(APP_NAME, "An operation is already running.")
            return
        w = self.workspace_tab.collect()
        c = self.crypto_tab.collect()
        self.engine = AnalysisEngine(
            op, self.events, file_path=w["binary_path"], value=c["value"],
            key=c["key"], encoding=c["encoding"],
            flag_format=w["flag_format"] or "flag{")
        self.engine.start()
        self._log(f"[{op}] started…")

    def _run_crypto_op(self) -> None:
        self._run_engine_op(self.crypto_tab.collect()["op"])

    # ------------------------------------------------------------- writeup
    def _export_writeup(self) -> None:
        ch = self._collect_challenge()
        if self.challenge_id is not None:
            ch.id = self.challenge_id
        records = (self.db.list_operations(self.challenge_id)
                   if self.challenge_id is not None else [])
        if not records:
            records = self._session_records
        directory = self.writeup_tab.export_dir_var.get().strip()
        if not directory:
            messagebox.showwarning(APP_NAME, "Choose an export folder.")
            return
        try:
            from app.core.report import export_all
            paths = export_all(ch.to_dict(), records, directory)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        messagebox.showinfo(APP_NAME, "Writeup exported (downloaded):\n" +
                            "\n".join(f"• {p}" for p in paths.values()))
        self.state.log_memory(f"writeup exported for {ch.name}")

    # ------------------------------------------------------------- event loop
    @property
    def _session_records(self) -> list:
        return getattr(self, "_session_records_cache", [])

    def _poll_events(self) -> None:
        try:
            while True:
                ev = self.events.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._poll_events)

    def _handle_event(self, ev: dict) -> None:
        typ = ev["type"]
        if typ == "status":
            self._log(ev["message"])
        elif typ == "log":
            self.ops_tab.log(ev["message"])
        elif typ == "binary_loaded":
            info = ev["info"]
            self.analysis_tab.set_info(info)
            self.analysis_tab.set_strings(info.strings)
            try:
                with open(info.path, "rb") as fh:
                    self.analysis_tab.set_hex(fh.read(4096))
            except Exception:
                pass
        elif typ == "strings_ready":
            self.analysis_tab.set_strings(ev["strings"])
        elif typ == "entropy_ready":
            self.analysis_tab.set_entropy(ev["entropy"], ev["blocks"])
        elif typ == "disasm_ready":
            self.analysis_tab.set_disasm(ev["text"])
        elif typ == "op_done":
            rec: AnalysisRecord = ev["record"]
            if ev.get("error"):
                self.ops_tab.log(f"[{rec.tool}] error: {ev['error']}", "warn")
            self.ops_tab.add_record(rec.to_dict())
            self._session_records_cache = (getattr(self, "_session_records_cache", [])
                                           + [rec.to_dict()])
            if self.challenge_id is not None:
                self.db.insert_operation(self.challenge_id, rec)
            if rec.tool == "encoding" and rec.full_output:
                self.crypto_tab.set_output(rec.full_output)
            self._write_state()

    # ---------------------------------------------------------------- helpers
    def _load_last_config(self) -> None:
        self.workspace_tab.apply({
            "challenge_name": self.settings.get("challenge_name", ""),
            "category": self.settings.get("category", "rev"),
            "event": self.settings.get("event", ""),
            "flag_format": self.settings.get("flag_format", "flag{"),
            "binary_path": self.settings.get("binary_path", ""),
        })
        self.history_tab.refresh()

    def _write_state(self) -> None:
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": "analyzing" if (self.engine and self.engine.is_alive()) else "idle",
            "Last activity": now_iso(),
            "Current challenge": (f"#{self.challenge_id} {self.challenge.name}"
                                  if self.challenge and self.challenge_id else "none"),
            "state.md": "live snapshot (this file)",
            "memory.md": "append-only history",
        })

    def _log(self, line: str) -> None:
        self.ops_tab.log(f"[app] {line}")

    # ----------------------------------------------------------------- close
    def _on_close(self) -> None:
        self.settings.update(self.workspace_tab.collect())
        self.settings.save()
        self.state.log_memory("GUI session ended")
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": "closed",
            "Last activity": now_iso(),
        })
        try:
            self.db.close()
        finally:
            self.root.destroy()


def run_gui() -> int:
    root = tk.Tk()
    app = RectApp(root)
    root.after(120, app._load_last_config)
    root.mainloop()
    return 0
