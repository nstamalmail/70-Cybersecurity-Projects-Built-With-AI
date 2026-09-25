"""WNA GUI tabs: Scope, Capture & Verify, Crack, Targets, Reports, Console."""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_data_dir, get_reports_dir
from app.gui.widgets import (ACCENT, FONT_FAMILY, add_text, log_to_text,
                             make_tree)


class ScopeTab(ttk.Frame):
    """Mandatory BSSID allowlist + audit metadata."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(1, weight=1)
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        ttk.Label(self, text="Audit name:").grid(row=0, column=0, sticky="w", **pad)
        self.name_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.name_var).grid(row=0, column=1,
                                                         sticky="ew", **pad)

        ttk.Label(self, text="Adapter / iface:").grid(row=1, column=0, sticky="w", **pad)
        row = ttk.Frame(self, style="TFrame")
        row.grid(row=1, column=1, sticky="ew", **pad)
        self.adapter_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.adapter_var, width=28).pack(side="left")
        ttk.Label(row, text=" e.g. wlan0 / wlan0mon (monitor mode is managed "
                            "by airmon-ng on the capture host)",
                  foreground="#7f849c").pack(side="left", padx=6)

        ttk.Label(self, text="Scope allowlist\n(one BSSID or\nBSSID=ESSID per\nline) —\nMANDATORY:").grid(
            row=2, column=0, sticky="nw", **pad)
        wrap_a = ttk.Frame(self, style="TFrame")
        wrap_a.grid(row=2, column=1, sticky="nsew", **pad)
        self.allow_text = add_text(wrap_a, height=8)
        self.rowconfigure(2, weight=1)

        brow = ttk.Frame(self, style="TFrame")
        brow.grid(row=3, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Button(brow, text="⬆ Import allowlist…",
                   command=self._import_allowlist).pack(side="left")
        ttk.Button(brow, text="💾 Export allowlist…",
                   command=self._export_allowlist).pack(side="left", padx=6)

        warn = ("Scope control: only BSSIDs on this allowlist may be assessed. "
                "Deauthentication/disruption of non-lab networks is prohibited "
                "and this tool records your declared scope in the audit report.")
        ttk.Label(self, text=warn, foreground="#f9e2c9", background="#3a3045",
                  wraplength=980, justify="left", padding=8).grid(
            row=4, column=0, columnspan=2, sticky="ew", **pad)

    def _import_allowlist(self):
        path = filedialog.askopenfilename(
            title="Import allowlist", initialdir=SAMPLES_DIR,
            filetypes=[("Text/JSON", "*.txt *.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
            if path.endswith(".json"):
                doc = json.loads(content)
                items = doc.get("allowlist", doc.get("bssids", []))
                lines = [item if isinstance(item, str) else
                         f"{item.get('bssid')}={item.get('essid', '')}"
                         for item in items]
                content = "\n".join(lines)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not read allowlist: {exc}")
            return
        self.allow_text.delete("1.0", "end")
        self.allow_text.insert("1.0", content)

    def _export_allowlist(self):
        path = filedialog.asksaveasfilename(
            title="Export allowlist", defaultextension=".json",
            initialfile="allowlist.json",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return
        try:
            if path.endswith(".json"):
                doc = {"allowlist": self.get_allowlist()}
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh, indent=2)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(self.get_allowlist()))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Export failed: {exc}")

    def get_allowlist(self) -> list:
        """Return normalized entries like 'aa:bb:cc:dd:ee:ff' or
        'aa:bb:cc:dd:ee:ff=MyLabAP'."""
        out = []
        for line in self.allow_text.get("1.0", "end").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
        return out

    def get_bssids(self) -> list:
        out = []
        for entry in self.get_allowlist():
            bssid = entry.split("=", 1)[0].strip().lower()
            if bssid:
                out.append(bssid)
        return out

    def collect(self) -> dict:
        return {
            "audit_name": self.name_var.get().strip() or "lab audit",
            "adapter": self.adapter_var.get().strip(),
            "allowlist": self.get_allowlist(),
            "bssids": self.get_bssids(),
        }


class CaptureTab(ttk.Frame):
    """Capture file upload + verification gate + hash conversion."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self.on_verify = None
        self.on_convert = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        row0 = ttk.LabelFrame(self, text=" Capture file (.cap / .pcapng) — "
                                         "manual upload from your lab capture host ",
                              padding=8)
        row0.grid(row=0, column=0, sticky="ew", **pad)
        self.path_var = tk.StringVar()
        ttk.Entry(row0, textvariable=self.path_var).pack(side="left", fill="x",
                                                         expand=True)
        ttk.Button(row0, text="📂 Browse…", command=self._browse).pack(side="left", padx=6)
        ttk.Button(row0, text="🔎 Verify handshake", style="Accent.TButton",
                   command=self._verify).pack(side="left", padx=6)
        ttk.Button(row0, text="🧬 Convert to hashcat 22000",
                   command=self._convert).pack(side="left")

        gate = ttk.LabelFrame(self, text=" Verification gate ", padding=8)
        gate.grid(row=1, column=0, sticky="ew", **pad)
        self.gate_var = tk.StringVar(value="no capture verified yet — cracking "
                                           "controls stay disabled")
        ttk.Label(gate, textvariable=self.gate_var,
                  font=(FONT_FAMILY, 11, "bold")).pack(anchor="w")

        det = ttk.LabelFrame(self, text=" Verification detail ", padding=8)
        det.grid(row=2, column=0, sticky="ew", **pad)
        self.detail_vars = {}
        for key, label in (("bssid", "BSSID"), ("essid", "ESSID"),
                           ("encryption", "Encryption"),
                           ("eapol", "EAPOL-Key frames"),
                           ("messages", "Messages present"),
                           ("pmkid", "PMKID")):
            row = ttk.Frame(det, style="TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f"{label}:", width=18).pack(side="left")
            var = tk.StringVar(value="—")
            self.detail_vars[key] = var
            ttk.Label(row, textvariable=var).pack(side="left")
        self.notes_var = tk.StringVar(value="")
        ttk.Label(det, textvariable=self.notes_var, foreground="#7f849c",
                  wraplength=900, justify="left").pack(anchor="w", pady=(4, 0))

        hashf = ttk.LabelFrame(self, text=" Converted hash lines (hashcat "
                                          "mode 22000 / report evidence) ", padding=8)
        hashf.grid(row=3, column=0, sticky="nsew", **pad)
        wrap_h = ttk.Frame(hashf, style="TFrame")
        wrap_h.pack(fill="both", expand=True)
        self.hash_text = add_text(wrap_h, height=8)

    def _browse(self):
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Select capture file", initialdir=initial,
            filetypes=[("Capture", "*.cap *.pcapng *.pcap"), ("All files", "*.*")])
        if path:
            self.path_var.set(path)

    def _verify(self):
        if self.on_verify:
            self.on_verify()

    def _convert(self):
        if self.on_convert:
            self.on_convert()

    def set_result(self, vr) -> None:
        self.detail_vars["bssid"].set(vr.bssid or "—")
        self.detail_vars["essid"].set(vr.essid or "—")
        self.detail_vars["encryption"].set(vr.encryption)
        self.detail_vars["eapol"].set(str(vr.eapol_frames))
        self.detail_vars["messages"].set(", ".join(vr.messages_present) or "—")
        self.detail_vars["pmkid"].set("yes" if vr.pmkid_captured else "no")
        self.notes_var.set(vr.notes or "")
        if vr.handshake_captured or vr.pmkid_captured:
            self.gate_var.set("✔ " + vr.summary())
        else:
            self.gate_var.set("✖ " + vr.summary())

    def set_gate_locked(self, text: str):
        self.gate_var.set("🔒 " + text)

    def set_hashes(self, lines: list):
        self.hash_text.configure(state="normal")
        self.hash_text.delete("1.0", "end")
        self.hash_text.insert("1.0", "\n".join(lines) or "(no convertible pairs)")
        self.hash_text.configure(state="disabled")


class CrackTab(ttk.Frame):
    """Cracking console — gated by the verification check."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self.on_start = None
        self.on_stop = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        cfg = ttk.LabelFrame(self, text=" Internal PSK verification (wordlist "
                                        "→ M1/M2 MIC check, stdlib PBKDF2) ", padding=8)
        cfg.grid(row=0, column=0, sticky="ew", **pad)
        ttk.Label(cfg, text="Wordlist:").pack(side="left")
        self.wordlist_var = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.wordlist_var, width=44).pack(
            side="left", padx=(4, 6))
        ttk.Button(cfg, text="📂…", width=4,
                   command=self._browse_wordlist).pack(side="left")
        ttk.Label(cfg, text="Workers:").pack(side="left", padx=(12, 2))
        self.workers_var = tk.IntVar(value=4)
        ttk.Spinbox(cfg, from_=1, to=16, textvariable=self.workers_var,
                    width=4).pack(side="left")
        self.start_btn = ttk.Button(cfg, text="▶ Start", style="Accent.TButton",
                                    command=self._start)
        self.start_btn.pack(side="left", padx=12)
        self.stop_btn = ttk.Button(cfg, text="⏹ Stop", style="Danger.TButton",
                                   state="disabled", command=self._stop)
        self.stop_btn.pack(side="left")

        handoff = ttk.LabelFrame(self, text=" External tool handoff (detected "
                                            "on the capture host) ", padding=8)
        handoff.grid(row=1, column=0, sticky="ew", **pad)
        self.handoff_text = add_text(handoff, height=4)
        self.handoff_text.configure(state="disabled")

        prog = ttk.Frame(self, style="TFrame")
        prog.grid(row=2, column=0, sticky="ew", **pad)
        self.progress = ttk.Progressbar(prog, mode="indeterminate", length=260)
        self.progress.pack(side="left")
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(prog, textvariable=self.status_var,
                  foreground=ACCENT).pack(side="left", padx=10)
        self.tested_var = tk.StringVar(value="0 tested")
        ttk.Label(prog, textvariable=self.tested_var).pack(side="left", padx=6)

        resf = ttk.LabelFrame(self, text=" Result ", padding=8)
        resf.grid(row=3, column=0, sticky="nsew", **pad)
        self.result_var = tk.StringVar(value="—")
        ttk.Label(resf, textvariable=self.result_var,
                  font=(FONT_FAMILY, 13, "bold")).pack(anchor="w")
        ttk.Label(resf, text=("PSK verification only runs against handshakes "
                              "you captured in your own lab. Found keys go into "
                              "the audit report as posture evidence."),
                  foreground="#7f849c", wraplength=900,
                  justify="left").pack(anchor="w", pady=(6, 0))

    def _browse_wordlist(self):
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Select wordlist", initialdir=initial,
            filetypes=[("Text", "*.txt *.lst *.dict"), ("All files", "*.*")])
        if path:
            self.wordlist_var.set(path)

    def _start(self):
        if self.on_start:
            self.on_start()

    def _stop(self):
        if self.on_stop:
            self.on_stop()

    def set_running(self, running: bool):
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        if running:
            self.progress.start(40)
        else:
            self.progress.stop()

    def set_tested(self, n: int):
        self.tested_var.set(f"{n} tested")

    def set_result(self, found: str, duration: float = 0.0):
        if found:
            self.result_var.set(f"🚩 PSK FOUND: {found!r} ({duration:.1f}s)")
        else:
            self.result_var.set(f"not found ({duration:.1f}s)")

    def set_handoff(self, text: str):
        self.handoff_text.configure(state="normal")
        self.handoff_text.delete("1.0", "end")
        self.handoff_text.insert("1.0", text)
        self.handoff_text.configure(state="disabled")


class TargetsTab(ttk.Frame):
    """Assessed targets for the current audit."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.on_save_target = None
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.tree = make_tree(wrap, ("bssid", "essid", "ch", "enc",
                                     "handshake", "pmkid", "crack", "result"),
                              ("BSSID", "ESSID", "Ch", "Encryption",
                               "Handshake", "PMKID", "Crack", "Result"),
                              (150, 140, 46, 110, 150, 66, 110, 180))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btns, text="💾 Save verified capture as target",
                   command=self._save).pack(side="left")

    def _save(self):
        if self.on_save_target:
            self.on_save_target()

    def add_target(self, t: dict):
        self.tree.insert("", "end", values=(
            t.get("bssid", ""), t.get("essid", ""), t.get("channel", ""),
            t.get("encryption", ""),
            t.get("handshake_completeness", "none"),
            "yes" if t.get("pmkid_captured") else "no",
            t.get("crack_tool") or "—",
            t.get("crack_result") or "—"))


class ReportsTab(ttk.Frame):
    def __init__(self, master, db=None):
        super().__init__(master, style="TFrame")
        self.db = db
        self.on_export = None
        self.on_import_file = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.tree = make_tree(wrap, ("id", "started", "finished", "audit",
                                     "adapter", "targets"),
                              ("ID", "Started", "Finished", "Audit", "Adapter",
                               "Targets"),
                              (44, 140, 140, 240, 120, 70))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        ttk.Button(btns, text="↻ Refresh", command=self.refresh).pack(side="left")
        ttk.Button(btns, text="⬆ Import audit file…", style="Accent.TButton",
                   command=self._import).pack(side="left", padx=6)
        ttk.Button(btns, text="💾 Export audit report (HTML/CSV/JSON)…",
                   style="Accent.TButton", command=self._export).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Delete audit", style="Danger.TButton",
                   command=self._delete).pack(side="left", padx=6)

        hint = ttk.Label(self, text="Reports frame results as posture "
                                    "validation with hardening recommendations; "
                                    "exported files can be saved anywhere.",
                         foreground="#7f849c", wraplength=940, justify="left")
        hint.grid(row=2, column=0, sticky="w", padx=10, pady=(0, 10))

    def refresh(self):
        if not self.db:
            return
        self.tree.delete(*self.tree.get_children())
        for row in self.db.list_audits():
            self.tree.insert("", "end", values=(
                row["id"], row["started_at"], row["finished_at"] or "",
                row["audit_id"] or "", row["adapter"] or "",
                row["targets_count"] or 0))

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select an audit first.")
            return None
        return int(self.tree.item(sel[0], "values")[0])

    def _import(self):
        if self.on_import_file:
            self.on_import_file()

    def _export(self):
        aid = self._selected_id()
        if aid is not None and self.on_export:
            self.on_export(aid)

    def _delete(self):
        aid = self._selected_id()
        if aid is None or not self.db:
            return
        if messagebox.askyesno(APP_NAME, f"Delete audit #{aid}?"):
            self.db.delete_audit(aid)
            self.refresh()


class ConsoleTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._build()

    def _build(self):
        con = ttk.LabelFrame(self, text=" Console ", padding=4)
        con.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_text = add_text(con, height=20)
        self.log_text.tag_configure("warn", foreground="#f9e2af")
        self.log_text.tag_configure("ok", foreground="#a6e3a1")

    def log(self, line: str, tag: str = ""):
        log_to_text(self.log_text, line, tag)


class SettingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        card = ttk.LabelFrame(self, text=" Portable paths ", padding=10)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        wrap1 = ttk.Frame(card, style="TFrame")
        wrap1.pack(fill="both", expand=True)
        self.paths_text = add_text(wrap1, height=8)
        self.paths_text.insert("1.0", "starting…")

        mem = ttk.LabelFrame(self, text=" Recent memory (memory.md) ", padding=10)
        mem.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        wrap2 = ttk.Frame(mem, style="TFrame")
        wrap2.pack(fill="both", expand=True)
        self.memory_text = add_text(wrap2, height=10)

    def set_paths(self, mapping: dict):
        self.paths_text.configure(state="normal")
        self.paths_text.delete("1.0", "end")
        self.paths_text.insert("1.0", "\n".join(f"{k}: {v}" for k, v in mapping.items()))
        self.paths_text.configure(state="disabled")

    def refresh_memory(self, lines: list):
        self.memory_text.configure(state="normal")
        self.memory_text.delete("1.0", "end")
        self.memory_text.insert("1.0", "\n".join(lines) or "(empty)")
        self.memory_text.configure(state="disabled")
