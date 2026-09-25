"""Tab 4: Findings — table + request/response detail."""

from __future__ import annotations

from tkinter import ttk

from app.core.models import SEVERITY_ORDER, SEVERITIES
from app.gui.widgets import FONT_MONO, FONT_SM, Card, SEV_COLORS, add_text, make_tree


class FindingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=3)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()
        self._findings = []
        self._filter = "all"

    def _build(self):
        top = Card(self, "Findings")
        top.grid(row=0, column=0, sticky="nsew", padx=(10, 10), pady=(10, 5))

        bar = ttk.Frame(top.inner, style="TFrame")
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Severity filter:").pack(side="left")
        self.filter_var = ttk.Combobox(bar, values=["all"] + SEVERITIES,
                                       state="readonly", width=12)
        self.filter_var.set("all")
        self.filter_var.pack(side="left", padx=6)
        self.filter_var.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())
        ttk.Label(bar, text=f"Count: ", font=FONT_SM).pack(side="left", padx=(16, 0))
        self.count_var = ttk.Label(bar, text="0", font=FONT_SM, foreground="#89b4fa")
        self.count_var.pack(side="left")

        columns = ["sev", "cat", "tech", "point", "url", "status", "payload", "enc", "time"]
        self.tree = make_tree(top.inner, columns,
                              ["Severity", "Category", "Technique", "Point",
                               "URL", "Status", "Payload", "Enc", "Time"],
                              [90, 90, 130, 150, 260, 60, 160, 70, 90],
                              selectmode="browse")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_detail())

        bottom = Card(self, "Request / Response evidence")
        bottom.grid(row=1, column=0, sticky="nsew", padx=(10, 10), pady=(5, 10))
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(0, weight=1)

        # Card.inner already contains the pack-managed title label, so put a
        # packed content frame inside it and grid the panes within that frame
        # (never mix pack and grid under the same master).
        content = ttk.Frame(bottom.inner, style="TFrame")
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        req_frame = ttk.Frame(content, style="TFrame")
        req_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        resp_frame = ttk.Frame(content, style="TFrame")
        resp_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self.req_text = add_text(req_frame, height=10)
        self.resp_text = add_text(resp_frame, height=10)
        for txt in (self.req_text, self.resp_text):
            txt.configure(font=FONT_MONO, state="disabled")

    # ------------------------------------------------------------------ data
    def clear(self) -> None:
        self._findings = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.count_var.configure(text="0")
        self.req_text.configure(state="normal"); self.req_text.delete("1.0", "end"); self.req_text.configure(state="disabled")
        self.resp_text.configure(state="normal"); self.resp_text.delete("1.0", "end"); self.resp_text.configure(state="disabled")

    def add_finding(self, f: dict) -> None:
        self._findings.append(f)
        self._apply_filter()

    def set_findings(self, findings: list) -> None:
        self._findings = list(findings)
        self._apply_filter()

    def _apply_filter(self) -> None:
        self._filter = self.filter_var.get()
        for item in self.tree.get_children():
            self.tree.delete(item)
        shown = 0
        for f in self._findings:
            if self._filter != "all" and f.get("severity") != self._filter:
                continue
            shown += 1
            self.tree.insert("", "end", values=(
                f.get("severity", "").upper(),
                f.get("category", ""),
                f.get("technique", ""),
                f"{f.get('injection_kind', '')}:{f.get('injection_name', '')}",
                f.get("url", "")[:120],
                f.get("status", ""),
                f.get("payload", "")[:60],
                f.get("encoding", ""),
                f"{f.get('resp_time_ms', 0):.0f}ms",
            ), tags=(f.get("severity", "info"),))
        for sev in SEVERITIES:
            self.tree.tag_configure(sev, foreground=SEV_COLORS.get(sev, "#cdd6f4"))
        self.count_var.configure(text=str(shown))

    def _show_detail(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        # Map back through the filtered list.
        f = None
        cnt = 0
        for candidate in self._findings:
            if self._filter != "all" and candidate.get("severity") != self._filter:
                continue
            if cnt == idx:
                f = candidate
                break
            cnt += 1
        if not f:
            return
        for txt, key, title in ((self.req_text, "request", "REQUEST"),
                                (self.resp_text, "response", "RESPONSE (snippet)")):
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.insert("1.0", f"--- {title} ---\n{f.get('evidence', '')}\n\n{f.get(key, '')}")
            txt.configure(state="disabled")