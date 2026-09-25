"""WNA main window: scope enforcement, capture verification gate, cracking,
audit persistence and report export.

Threading contract: the cracker pushes events onto queue.Queue; the main
thread polls via root.after() and applies them to widgets.
"""

from __future__ import annotations

import os
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_base_dir, get_data_dir
from app.core.cracker import WordlistCracker, has_external_tools, CrackConfig
from app.core.models import AuditTarget, VerificationResult, WirelessAudit, now_iso
from app.gui.tabs import (CaptureTab, ConsoleTab, CrackTab, ReportsTab,
                          ScopeTab, SettingsTab, TargetsTab)
from app.gui.widgets import apply_theme
from app.storage.database import Database
from app.utils.state import StateStore

POLL_MS = 80


class WnaApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.db = Database()
        self.state = StateStore()
        self.events: "queue.Queue" = queue.Queue()
        self.verified: VerificationResult | None = None
        self.cracker: WordlistCracker | None = None
        self.audit_id: int | None = None
        self.current_targets: list = []

        apply_theme(root)
        root.title(f"{APP_NAME} — Wireless Network Auditor (lab AP) "
                   f"v{__version__}")
        root.geometry("1280x840")
        root.minsize(1060, 700)

        self._build_toolbar()
        self._build_tabs()
        self._wire_callbacks()

        self._log(f"{APP_NAME} started. Scope allowlist is mandatory; cracking "
                  "is gated on a verified complete handshake/PMKID.")
        self.state.log_memory("GUI session started")
        self._write_state()
        self.settings_tab.refresh_memory(self.state.read_memory())
        self._update_handoff()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_events()

    # ------------------------------------------------------------------ build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="📶 " + APP_NAME, font=("Segoe UI", 15, "bold"),
                  foreground="#89b4fa").pack(side="left")
        ttk.Label(bar, text=" Lab-scoped posture validation",
                  foreground="#7f849c").pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="🆕 New audit",
                   command=self._new_audit).pack(side="right", padx=(6, 0))

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.scope_tab = ScopeTab(self.notebook)
        self.capture_tab = CaptureTab(self.notebook)
        self.crack_tab = CrackTab(self.notebook)
        self.targets_tab = TargetsTab(self.notebook)
        self.reports_tab = ReportsTab(self.notebook, db=self.db)
        self.console_tab = ConsoleTab(self.notebook)
        self.settings_tab = SettingsTab(self.notebook)

        self.notebook.add(self.scope_tab, text="  1. Scope  ")
        self.notebook.add(self.capture_tab, text="  2. Capture & verify  ")
        self.notebook.add(self.crack_tab, text="  3. Crack (gated)  ")
        self.notebook.add(self.targets_tab, text="  4. Targets  ")
        self.notebook.add(self.reports_tab, text="  5. Reports  ")
        self.notebook.add(self.console_tab, text="  6. Console  ")
        self.notebook.add(self.settings_tab, text="  7. Settings  ")

        base = get_base_dir()
        self.settings_tab.set_paths({
            "Base dir": base,
            "state.md": os.path.join(base, "state.md"),
            "memory.md": os.path.join(base, "memory.md"),
            "Database": self.db.path,
            "Samples": SAMPLES_DIR,
        })

    def _wire_callbacks(self) -> None:
        self.capture_tab.on_verify = self._verify_capture
        self.capture_tab.on_convert = self._convert_hash
        self.crack_tab.on_start = self._start_crack
        self.crack_tab.on_stop = self._stop_crack
        self.targets_tab.on_save_target = self._save_target
        self.reports_tab.on_export = self._export_audit
        self.reports_tab.on_import_file = self._import_audit_file
        self.reports_tab.refresh()

    # ------------------------------------------------------------------ audit
    def _new_audit(self) -> None:
        s = self.scope_tab.collect()
        audit = WirelessAudit(audit_id=s["audit_name"], adapter=s["adapter"],
                              allowlist=s["allowlist"])
        self.audit_id = self.db.create_audit(audit)
        self.current_targets = []
        self.targets_tab.tree.delete(*self.targets_tab.tree.get_children())
        self.state.log_memory(f"audit started: #{self.audit_id} ({s['audit_name']})")
        self._log(f"New audit #{self.audit_id}: {s['audit_name']} — "
                  f"{len(s['bssids'])} allowlisted BSSID(s)")
        self.reports_tab.refresh()

    def _ensure_audit(self) -> None:
        if self.audit_id is None:
            self._new_audit()

    # ------------------------------------------------------------------ verify
    def _verify_capture(self) -> None:
        path = self.capture_tab.path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning(APP_NAME, f"Capture file not found:\n{path}")
            return
        # scope check: verified BSSID must be allowlisted (when allowlist used)
        bssids = self.scope_tab.get_bssids()
        from app.core.verifier import verify_capture
        vr = verify_capture(path)
        if vr.bssid and bssids and vr.bssid.lower() not in bssids:
            self._log(f"⛔ BSSID {vr.bssid} is NOT on the scope allowlist — "
                      "refusing to assess.")
            messagebox.showwarning(
                APP_NAME,
                f"The capture's AP ({vr.bssid}) is not on your scope "
                "allowlist. Add it in the Scope tab if it is your lab AP.")
            return
        self.verified = vr
        self.capture_tab.set_result(vr)
        self._log(f"verified: {vr.summary()} "
                  f"({vr.eapol_frames} EAPOL-Key frames, {vr.total_packets} packets)")
        if vr.handshake_captured or vr.pmkid_captured:
            self.state.log_memory(f"handshake verified: {vr.summary()}")
            self.notebook.select(self.crack_tab)
        else:
            self.notebook.select(self.capture_tab)

    def _convert_hash(self) -> None:
        path = self.capture_tab.path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning(APP_NAME, "Verify a capture file first.")
            return
        from app.core.verifier import convert_to_22000
        lines = convert_to_22000(path)
        self.capture_tab.set_hashes(lines)
        # save hash file next to reports for handoff
        if lines:
            out = os.path.join(get_data_dir(), f"{os.path.basename(path)}.hc22000")
            try:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
                self._log(f"hash file written: {out} ({len(lines)} line(s))")
            except Exception as exc:
                self._log(f"hash file write failed: {exc}")
        else:
            self._log("no convertible M1/M2 pair in this capture")

    # ------------------------------------------------------------------ crack
    def _update_handoff(self) -> None:
        tools = has_external_tools()
        lines = []
        for name, present in tools.items():
            lines.append(f"{'✔' if present else '✖'} {name}: "
                         f"{'available on PATH' if present else 'not found'}")
        lines.append("")
        lines.append("aircrack-ng : aircrack-ng -w wordlist.txt -b <BSSID> capture.cap")
        lines.append("hashcat     : hashcat -m 22000 hash.hc22000 wordlist.txt")
        self.crack_tab.set_handoff("\n".join(lines))

    def _start_crack(self) -> None:
        if self.verified is None:
            messagebox.showwarning(APP_NAME, "Verify a capture first (tab 2).")
            return
        if not (self.verified.handshake_captured or self.verified.pmkid_captured):
            messagebox.showwarning(
                APP_NAME,
                "Verification gate: a complete M1–M4 handshake or a PMKID is "
                "required before cracking controls unlock.")
            return
        s = self.scope_tab.collect()
        if not s["bssids"]:
            messagebox.showwarning(APP_NAME,
                                   "Scope allowlist is mandatory (tab 1).")
            return
        wordlist = self.crack_tab.wordlist_var.get().strip()
        if not wordlist:
            messagebox.showwarning(APP_NAME, "Select a wordlist file.")
            return
        self._ensure_audit()
        cfg = CrackConfig(wordlist_path=wordlist, essid=self.verified.essid,
                          workers=int(self.crack_tab.workers_var.get() or 4))
        self.cracker = WordlistCracker(self.verified, cfg, self.events)
        self.cracker.start()
        self.crack_tab.set_running(True)
        self.crack_tab.set_result("searching…")
        self._ensure_audit()

    def _stop_crack(self) -> None:
        if self.cracker:
            self.cracker.stop()

    def _save_target(self) -> None:
        if self.verified is None:
            messagebox.showwarning(APP_NAME, "Verify a capture first (tab 2).")
            return
        self._ensure_audit()
        t = AuditTarget(
            bssid=self.verified.bssid, essid=self.verified.essid,
            encryption=self.verified.encryption,
            handshake_captured=self.verified.handshake_captured,
            handshake_completeness=self.verified.handshake_completeness,
            messages_present=self.verified.messages_present,
            pmkid_captured=self.verified.pmkid_captured,
            hash_file=os.path.join(
                get_data_dir(),
                os.path.basename(self.verified.capture_path) + ".hc22000"),
            crack_attempted=bool(self.cracker),
            crack_tool="internal-py" if self.cracker else "",
            crack_result=self.cracker.state.found if self.cracker else "",
            crack_duration_seconds=self.cracker.state.duration
            if self.cracker else 0.0,
        )
        self.db.insert_target(self.audit_id, t)
        self.current_targets.append(t.to_dict())
        self.targets_tab.add_target(t.to_dict())
        self.db.finish_audit(self.audit_id, len(self.current_targets))
        self.state.log_memory(
            f"target saved: {t.essid or t.bssid} "
            f"({t.handshake_completeness}, crack={'found ' + t.crack_result if t.crack_result else 'no'})")
        self._log(f"target saved to audit #{self.audit_id}")
        self.reports_tab.refresh()

    # ------------------------------------------------------------------ reports
    def _export_audit(self, audit_db_id: int) -> None:
        from app.core.report import export_all
        audit = self.db.get_audit(audit_db_id)
        if not audit:
            return
        targets = self.db.list_targets(audit_db_id)
        audit["generated"] = now_iso()
        directory = filedialog.askdirectory(title="Choose export folder",
                                            initialdir=get_reports_dir())
        if not directory:
            return
        try:
            paths = export_all(audit, targets, directory)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")
            return
        messagebox.showinfo(APP_NAME, "Audit report exported (downloaded):\n" +
                            "\n".join(f"• {p}" for p in paths.values()))
        self.state.log_memory(f"audit report exported for #{audit_db_id}")

    def _import_audit_file(self) -> None:
        from app.core.report_import import parse_audit_doc
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Import audit file (JSON)", initialdir=initial,
            filetypes=[("JSON audit", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read JSON: {exc}")
            return
        targets_raw, meta = parse_audit_doc(doc)
        if not targets_raw:
            messagebox.showwarning(APP_NAME, "No usable targets found in file.")
            return
        audit = WirelessAudit(
            audit_id=meta.get("audit_id", "imported"),
            adapter=meta.get("adapter", ""),
            allowlist=meta.get("allowlist", []),
            capture_method=meta.get("capture_method", "import"),
            notes=meta.get("notes", ""))
        aid = self.db.create_audit(audit)
        for t in targets_raw:
            self.db.insert_target(aid, AuditTarget(
                bssid=t.get("bssid", ""), essid=t.get("essid", ""),
                channel=t.get("channel", 0), encryption=t.get("encryption", ""),
                handshake_captured=t.get("handshake_captured", False),
                handshake_completeness=t.get("handshake_completeness", "none"),
                pmkid_captured=t.get("pmkid_captured", False),
                hash_file=t.get("hash_file", ""),
                crack_attempted=t.get("crack_attempted", False),
                crack_tool=t.get("crack_tool", ""),
                crack_result=t.get("crack_result", ""),
                crack_duration_seconds=t.get("crack_duration_seconds", 0.0)))
        self.db.finish_audit(aid, len(targets_raw))
        self.reports_tab.refresh()
        self.state.log_memory(f"imported {len(targets_raw)} target(s) "
                              f"from {os.path.basename(path)} as audit #{aid}")
        if messagebox.askyesno(APP_NAME,
                               f"Imported {len(targets_raw)} target(s) as "
                               f"audit #{aid}.\n\nExport the report now?"):
            self._export_audit(aid)

    # ------------------------------------------------------------- event loop
    def _poll_events(self) -> None:
        try:
            while True:
                ev = self.events.get_nowait()
                typ = ev.get("type")
                if typ == "log":
                    self._log(ev["message"])
                elif typ == "crack_progress":
                    self.crack_tab.set_tested(ev.get("tested", 0))
                elif typ == "crack_done":
                    self.crack_tab.set_running(False)
                    duration = self.cracker.state.duration if self.cracker else 0.0
                    found = ev.get("found", "")
                    self.crack_tab.set_result(found, duration)
                    self._write_state()
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._poll_events)

    # ---------------------------------------------------------------- helpers
    def _write_state(self) -> None:
        self.state.write_state({
            "App": f"{APP_NAME} v{__version__}",
            "Status": ("cracking" if (self.cracker and self.cracker.state.running)
                       else "idle"),
            "Last activity": now_iso(),
            "Current audit": f"#{self.audit_id}" if self.audit_id else "none",
            "Verified capture": (self.verified.summary()
                                 if self.verified else "none"),
            "state.md": "live snapshot (this file)",
            "memory.md": "append-only history",
        })

    def _log(self, line: str) -> None:
        self.console_tab.log(line)

    # ----------------------------------------------------------------- close
    def _on_close(self) -> None:
        if self.cracker:
            self.cracker.stop()
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
    app = WnaApp(root)
    root.mainloop()
    return 0
