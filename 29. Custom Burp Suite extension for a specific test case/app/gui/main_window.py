"""CBSEF main window: bridge lifecycle, findings flow, analysis wiring.

Threading contract: the bridge server pushes findings into queue.Queue; the
main thread polls via root.after() and applies them to widgets.
"""

from __future__ import annotations

import json
import os
import queue
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_base_dir, get_data_dir
from app.core import engine as eng
from app.core.bridge import BridgeServer
from app.core.models import CandidateFinding, now_iso
from app.gui.tabs import (ConfigTab, ConsoleTab, InspectorTab,
                          LiveFindingsTab, ReportsTab, SettingsTab)
from app.gui.widgets import apply_theme
from app.storage.database import Database
from app.utils.state import StateStore

POLL_MS = 80


class CbsefApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.db = Database()
        self.state = StateStore()
        self.events: "queue.Queue" = queue.Queue()
        self.bridge: BridgeServer | None = None
        self.session_id: int | None = None
        self.findings: list = []                # dicts for the table
        self.findings_by_iid: dict = {}
        self._iid_seq = 0

        apply_theme(root)
        root.title(f"{APP_NAME} — Burp Extension Companion "
                   f"(mass-assignment test case) v{__version__}")
        root.geometry("1280x820")
        root.minsize(1040, 680)

        self._build_toolbar()
        self._build_tabs()
        self._wire_callbacks()

        self._log(f"{APP_NAME} companion started. Start the bridge, then let "
                  "the Burp extension push findings — or analyze pasted "
                  "requests in the Inspector tab.")
        self.state.log_memory("GUI session started")
        self._write_state()
        self.settings_tab.refresh_memory(self.state.read_memory())

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    # ------------------------------------------------------------------ build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="🧲 " + APP_NAME, font=("Segoe UI", 15, "bold"),
                  foreground="#89b4fa").pack(side="left")
        ttk.Label(bar, text=" Passive-first, human-confirmed findings",
                  foreground="#7f849c").pack(side="left", padx=(8, 0))

        ttk.Button(bar, text="🆕 New session",
                   command=self._new_session).pack(side="right", padx=(6, 0))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.config_tab = ConfigTab(self.notebook)
        self.findings_tab = LiveFindingsTab(self.notebook)
        self.inspector_tab = InspectorTab(self.notebook)
        self.reports_tab = ReportsTab(self.notebook, db=self.db)
        self.console_tab = ConsoleTab(self.notebook)
        self.settings_tab = SettingsTab(self.notebook)

        self.notebook.add(self.config_tab, text="  1. Config  ")
        self.notebook.add(self.findings_tab, text="  2. Live findings  ")
        self.notebook.add(self.inspector_tab, text="  3. Inspector  ")
        self.notebook.add(self.reports_tab, text="  4. Reports  ")
        self.notebook.add(self.console_tab, text="  5. Console  ")
        self.notebook.add(self.settings_tab, text="  6. Settings  ")

        base = get_base_dir()
        self.settings_tab.set_paths({
            "Base dir": base,
            "state.md": os.path.join(base, "state.md"),
            "memory.md": os.path.join(base, "memory.md"),
            "Database": self.db.path,
            "Samples": SAMPLES_DIR,
        })

    def _wire_callbacks(self) -> None:
        self.config_tab.on_start_bridge = self._start_bridge
        self.config_tab.on_stop_bridge = self._stop_bridge
        self.findings_tab.on_confirm = lambda: self._set_status("confirmed")
        self.findings_tab.on_reject = lambda: self._set_status("false_positive")
        self.findings_tab.on_clear = self._clear_list
        self.findings_tab.tag_colors()
        self.findings_tab.filter_var.trace_add(
            "write", lambda *_: self.findings_tab.refresh_filter(
                self.findings_by_iid))
        self.inspector_tab.on_analyze = self._analyze_request
        self.inspector_tab.on_build_probe = self._build_probes
        self.reports_tab.on_export = self._export_session
        self.reports_tab.on_import_file = self._import_findings_file
        self.reports_tab.refresh()

    # ---------------------------------------------------------------- session
    def _new_session(self) -> None:
        c = self.config_tab.collect()
        case = c["test_cases"][0] if c["test_cases"] else "all"
        self.session_id = self.db.create_session(f"session {now_iso()}", case)
        self.state.log_memory(f"session started: #{self.session_id} ({case})")
        self._log(f"New session #{self.session_id} (test case: {case})")
        self.reports_tab.refresh()

    # ---------------------------------------------------------------- bridge
    def _start_bridge(self) -> None:
        c = self.config_tab.collect()
        if self.bridge:
            self._log("Bridge already running.")
            return
        try:
            # log_fn runs on bridge worker threads — never touch Tk there;
            # route messages through the event queue instead.
            self.bridge = BridgeServer(
                port=c["bridge_port"], token=c["bridge_token"],
                findings_out=self.events,
                log_fn=lambda m: self.events.put({"type": "log", "message": m}))
            self.bridge.start()
        except Exception as exc:
            self.bridge = None
            messagebox.showerror(APP_NAME, f"Could not start bridge: {exc}")
            return
        self.config_tab.set_bridge_status(
            f"running on 127.0.0.1:{self.bridge.actual_port}", True)
        self.state.log_memory(f"bridge started on port {self.bridge.actual_port}")

    def _stop_bridge(self) -> None:
        if self.bridge:
            self.bridge.stop()
            self.bridge = None
            self.config_tab.set_bridge_status("stopped", False)
            self._log("Bridge stopped.")
            self.state.log_memory("bridge stopped")

    # -------------------------------------------------------------- findings
    def _store_finding(self, f: CandidateFinding) -> int:
        if self.session_id is None:
            self._new_session()
        f.session_id = self.session_id
        return self.db.insert_finding(self.session_id, f)

    def _add_finding_row(self, f: CandidateFinding, db_id: int) -> None:
        self._iid_seq += 1
        iid = f"f{self._iid_seq}"
        f.id = db_id
        d = f.to_dict()
        self.findings.append(d)
        self.findings_by_iid[iid] = d
        self.findings_tab.add_finding(d, iid)
        self._log(f"⚠ candidate: {f.summary()}")

    def _selected_iid(self):
        sel = self.findings_tab.tree.selection()
        return sel[0] if sel else None

    def _set_status(self, status: str) -> None:
        iid = self._selected_iid()
        if not iid:
            messagebox.showinfo(APP_NAME, "Select a finding first.")
            return
        f = self.findings_by_iid.get(iid)
        if not f:
            return
        f["status"] = status
        if f.get("id") is not None:
            self.db.set_status(f["id"], status)
        self.findings_tab.update_row_status(iid, status)
        self._log(f"finding {f.get('finding_id', '')[:8]} → {status}")
        self.state.log_memory(f"finding {f.get('finding_id', '')[:8]} → {status}")

    def _clear_list(self) -> None:
        self.findings_tab.clear()
        self.findings_by_iid.clear()

    # -------------------------------------------------------------- inspector
    def _analyze_request(self) -> None:
        raw = self.inspector_tab.get_request()
        if not raw:
            messagebox.showwarning(APP_NAME, "Paste a raw request first.")
            return
        c = self.config_tab.collect()
        cases = c["test_cases"] or ["mass_assignment"]
        pieces = []
        findings = []
        if "mass_assignment" in cases:
            probes = eng.mass_assignment_probes(raw)
            pieces.append(f"mass-assignment: {len(probes)} probe(s) can be built "
                          "for this JSON request")
            if probes:
                pieces.append("  probes: " + "; ".join(p.name for p in probes))
        if "jwt_confusion" in cases:
            f = eng.analyze_jwt_confusion(raw)
            if f:
                findings.append(f)
                pieces.append("jwt: " + f.signal_description)
        if not pieces:
            pieces.append("No signals from the selected analyzers. For "
                          "mass-assignment, ensure the request has a JSON body.")
        self.inspector_tab.set_evidence("\n".join(pieces))
        for f in findings:
            db_id = self._store_finding(f)
            self._add_finding_row(f, db_id)
        self.notebook.select(self.inspector_tab)

    def _build_probes(self) -> None:
        raw = self.inspector_tab.get_request()
        probes = eng.mass_assignment_probes(raw)
        if not probes:
            self.inspector_tab.set_probes(
                "No probes built — the request needs a JSON body.")
            return
        blocks = []
        for p in probes:
            blocks.append(f"### {p.name} — {p.description}\n\n{p.raw_request}\n")
        self.inspector_tab.set_probes("\n".join(blocks))
        self._log(f"{len(probes)} probe(s) built — send them via Repeater and "
                  "paste the responses here for differential analysis.")

    # ---------------------------------------------------------------- reports
    def _export_session(self, session_id: int) -> None:
        from app.core.report import export_all
        session = self.db.get_session(session_id)
        if not session:
            return
        findings = self.db.list_findings(session_id)
        session["generated"] = now_iso()
        directory = filedialog.askdirectory(title="Choose export folder")
        if not directory:
            return
        try:
            paths = export_all(session, findings, directory)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        messagebox.showinfo(APP_NAME, "Report exported (downloaded):\n" +
                            "\n".join(f"• {p}" for p in paths.values()))
        self.state.log_memory(f"report exported for session #{session_id}")

    def _import_findings_file(self) -> None:
        from app.core.report_import import parse_findings_doc
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Import findings file (JSON)", initialdir=initial,
            filetypes=[("JSON findings", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read JSON: {exc}")
            return
        raw_findings, meta = parse_findings_doc(doc)
        if not raw_findings:
            messagebox.showwarning(APP_NAME, "No usable findings found in file.")
            return
        sid = self.db.create_session(meta.get("name", "imported"),
                                     meta.get("test_case", "all"))
        for item in raw_findings:
            f = CandidateFinding(
                finding_id=item.get("finding_id", ""),
                test_case=item.get("test_case", "mass_assignment"),
                url=item.get("url", ""), method=item.get("method", "POST"),
                endpoint=item.get("endpoint", ""),
                parameter=item.get("parameter", ""),
                confidence=item.get("confidence", "medium"),
                status=item.get("status", "candidate"),
                signal_description=item.get("signal_description", ""),
                baseline_request=item.get("baseline_request", ""),
                baseline_response=item.get("baseline_response", ""),
                probe_request=item.get("probe_request", ""),
                probe_response=item.get("probe_response", ""),
                differential=item.get("differential") or {},
                remediation=item.get("remediation", ""),
            )
            self.db.insert_finding(sid, f)
        self.db.finish_session(sid, len(raw_findings))
        self.reports_tab.refresh()
        self.state.log_memory(f"imported {len(raw_findings)} findings "
                              f"from {os.path.basename(path)} as session #{sid}")
        if messagebox.askyesno(APP_NAME,
                               f"Imported {len(raw_findings)} finding(s) as "
                               f"session #{sid}.\n\nExport the report now?"):
            self._export_session(sid)

    # ------------------------------------------------------------- event loop
    def _poll_events(self) -> None:
        try:
            while True:
                item = self.events.get_nowait()
                if isinstance(item, CandidateFinding):
                    db_id = self._store_finding(item)
                    self._add_finding_row(item, db_id)
                elif isinstance(item, dict) and item.get("type") == "log":
                    self._log(item["message"])
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._poll_events)

    # ---------------------------------------------------------------- helpers
    def _write_state(self) -> None:
        self.state.write_state({
            "App": f"{APP_NAME} companion v{__version__}",
            "Status": "listening" if self.bridge else "idle",
            "Last activity": now_iso(),
            "Current session": f"#{self.session_id}" if self.session_id else "none",
            "Findings in table": len(self.findings),
            "state.md": "live snapshot (this file)",
            "memory.md": "append-only history",
        })

    def _log(self, line: str) -> None:
        self.console_tab.log(line)

    # ----------------------------------------------------------------- close
    def _on_close(self) -> None:
        self._stop_bridge()
        self.state.log_memory("GUI session ended")
        self.state.write_state({
            "App": f"{APP_NAME} companion v{__version__}",
            "Status": "closed",
            "Last activity": now_iso(),
        })
        try:
            self.db.close()
        finally:
            self.root.destroy()


def run_gui() -> int:
    root = tk.Tk()
    app = CbsefApp(root)
    root.mainloop()
    return 0
