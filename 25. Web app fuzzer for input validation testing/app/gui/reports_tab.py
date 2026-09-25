"""Tab 5: Reports — scan history table, findings import, export buttons."""

from __future__ import annotations

import json
import os
from tkinter import filedialog, messagebox, ttk

from app.core.report import export_all
from app.gui.widgets import Card, make_tree

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
FINDING_FIELDS = ("category", "technique", "severity", "injection_kind",
                  "injection_name", "payload", "encoding", "url", "status",
                  "resp_len", "resp_time_ms", "evidence", "request", "response")


class ReportsTab(ttk.Frame):
    def __init__(self, master, db=None):
        super().__init__(master, style="TFrame")
        self.db = db
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)
        self._build()

    def _build(self):
        card = Card(self, "Scan history (SQLite)")
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))

        self.scans_tree = make_tree(
            card.inner,
            ("id", "started", "finished", "target", "requests", "findings", "errors"),
            ("ID", "Started", "Finished", "Target", "Requests", "Findings", "Errors"),
            (50, 130, 130, 320, 90, 90, 70),
            selectmode="browse",
        )

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btns, text="↻ Refresh", command=self.refresh).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="📄 Load into Findings tab", command=self._load_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="⬆ Import findings file…", style="Accent.TButton",
                   command=self._import_findings_file).pack(side="left", padx=6)
        ttk.Button(btns, text="💾 Export HTML/CSV/JSON…", style="Accent.TButton",
                   command=self._export_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Delete selected", style="Danger.TButton",
                   command=self._delete_selected).pack(side="left", padx=6)

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        if not self.db:
            return
        for item in self.scans_tree.get_children():
            self.scans_tree.delete(item)
        for row in self.db.list_scans():
            self.scans_tree.insert("", "end", values=(
                row["id"], row["started_at"], row["finished_at"] or "",
                row["target"], row["total_requests"], row["findings_count"], row["errors"],
            ))

    def _selected_scan_id(self):
        sel = self.scans_tree.selection()
        if not sel:
            messagebox.showinfo("WebFuzzer", "Select a scan first.")
            return None
        return int(self.scans_tree.item(sel[0], "values")[0])

    def _load_selected(self) -> None:
        sid = self._selected_scan_id()
        if sid is None:
            return
        findings = self.db.list_findings(sid)
        cb = getattr(self, "on_load_findings", None)
        if cb:
            cb(sid, findings)

    # ---------------------------------------------------- manual data import
    def _import_findings_file(self) -> None:
        """Import findings from a JSON file into the DB as a new scan.

        Lets the user generate/export a report from manually prepared data
        (e.g. samples/sample_findings.json) without running a live scan.
        """
        from app.config import SAMPLES_DIR

        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else None
        path = filedialog.askopenfilename(
            title="Import findings file (JSON)", initialdir=initial,
            filetypes=[("JSON findings", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("WebFuzzer", f"Could not read JSON: {exc}")
            return

        findings, scan_meta = self._parse_findings_doc(doc)
        if not findings:
            messagebox.showwarning("WebFuzzer",
                                   "No usable findings found.\nExpected a JSON object "
                                   "with a 'findings' list (or a top-level list).")
            return
        if self.db is None:
            messagebox.showerror("WebFuzzer", "Database not available.")
            return

        scan_id = self.db.create_scan({"to_dict": lambda: scan_meta},
                                      scan_meta.get("target", "imported"))
        for f in findings:
            self.db.insert_finding(scan_id, f)
        self.db.finish_scan(scan_id, scan_meta.get("total_requests", len(findings)),
                            len(findings), scan_meta.get("errors", 0))
        self.refresh()
        self.scans_tree.selection_set(
            self.scans_tree.get_children()[0]) if self.scans_tree.get_children() else None

        cb = getattr(self, "on_imported_scan", None)
        if cb:
            cb(scan_id, self.db.list_findings(scan_id))
        self._maybe_export(scan_id, scan_meta, len(findings), source=path)

    @staticmethod
    def _parse_findings_doc(doc) -> tuple:
        """Accepts {scan: {...}, findings: [...]} or a bare list of findings."""
        if isinstance(doc, list):
            raw_findings, scan_meta = doc, {"target": "imported", "notes": "bare list import"}
        elif isinstance(doc, dict):
            raw_findings = doc.get("findings", [])
            scan_meta = dict(doc.get("scan", {}) or {})
            scan_meta.setdefault("target", doc.get("target", "imported"))
            scan_meta.setdefault("started_at", doc.get("started_at", ""))
            scan_meta.setdefault("finished_at", doc.get("finished_at", ""))
        else:
            return [], {}

        from app.core.models import Finding

        out = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "info")).lower()
            if sev not in VALID_SEVERITIES:
                sev = "info"
            kwargs = {k: item.get(k, "" if k not in ("status", "resp_len") else 0)
                      for k in FINDING_FIELDS}
            kwargs["severity"] = sev
            try:
                kwargs["status"] = int(kwargs.get("status") or 0)
            except (TypeError, ValueError):
                kwargs["status"] = 0
            try:
                kwargs["resp_len"] = int(kwargs.get("resp_len") or 0)
            except (TypeError, ValueError):
                kwargs["resp_len"] = 0
            try:
                kwargs["resp_time_ms"] = float(kwargs.get("resp_time_ms") or 0)
            except (TypeError, ValueError):
                kwargs["resp_time_ms"] = 0.0
            try:
                out.append(Finding(**kwargs))
            except Exception:
                continue
        return out, scan_meta

    def _maybe_export(self, scan_id: int, scan_meta: dict, count: int, source: str = "") -> None:
        """Offer immediate report export right after import."""
        if not messagebox.askyesno(
                "WebFuzzer",
                f"Imported {count} finding(s) as scan #{scan_id}"
                + (f" from\n{source}" if source else "")
                + "\n\nGenerate the HTML/CSV/JSON report now?"):
            return
        scan = self.db.get_scan(scan_id) if self.db else scan_meta
        findings = self.db.list_findings(scan_id) if self.db else []
        directory = filedialog.askdirectory(title="Choose export folder")
        if not directory:
            return
        try:
            paths = export_all(scan, findings, directory,
                               started=scan.get("started_at", ""),
                               finished=scan.get("finished_at", ""))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("WebFuzzer", f"Export failed: {exc}")
            return
        messagebox.showinfo("WebFuzzer",
                            "Report exported:\n" + "\n".join(f"• {p}" for p in paths.values()))
        log = getattr(self, "on_memory_log", None)
        if log:
            log(f"report exported for imported scan #{scan_id}")

    # ---------------------------------------------------------------- export
    def _export_selected(self) -> None:
        sid = self._selected_scan_id()
        if sid is None:
            return
        scan = self.db.get_scan(sid)
        if not scan:
            return
        findings = self.db.list_findings(sid)
        default_dir = os.path.join(os.getcwd(), "reports")
        directory = filedialog.askdirectory(title="Choose export folder", initialdir=default_dir)
        if not directory:
            return
        try:
            paths = export_all(scan, findings, directory,
                               started=scan.get("started_at", ""),
                               finished=scan.get("finished_at", ""))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("WebFuzzer", f"Export failed: {exc}")
            return
        messagebox.showinfo("WebFuzzer",
                            "Exported:\n" + "\n".join(f"• {p}" for p in paths.values()))
        log = getattr(self, "on_memory_log", None)
        if log:
            log(f"report exported for scan #{sid}")

    def _delete_selected(self) -> None:
        sid = self._selected_scan_id()
        if sid is None:
            return
        if messagebox.askyesno("WebFuzzer", f"Delete scan #{sid} and its findings?"):
            self.db.delete_scan(sid)
            self.refresh()
