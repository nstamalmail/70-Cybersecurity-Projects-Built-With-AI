"""Process Monitor tab: live table, inspect dialog, kill action."""

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from ...core.utils import human_size, ts_str
from ..widgets import SEV_COLORS, make_tree


class ProcessTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        self._build()

    def _build(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh Now", command=self.refresh_now).pack(
            side="left", padx=2)
        ttk.Button(bar, text="Inspect Selected", command=self._inspect).pack(
            side="left", padx=2)
        ttk.Button(bar, text="Kill Selected…", command=self._kill).pack(
            side="left", padx=2)
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=28)
        entry.pack(side="right", padx=2)
        ttk.Label(bar, text="Filter:").pack(side="right")
        self.filter_var.trace_add("write", lambda *_: self.redraw())
        self.suspicious_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Suspicious only",
                        variable=self.suspicious_only,
                        command=self.redraw).pack(side="right", padx=8)

        frame, self.tree = make_tree(self, [
            ("pid", "PID", 70, "e"),
            ("ppid", "PPID", 70, "e"),
            ("name", "Name", 160, "w"),
            ("sev", "Flag", 60, "center"),
            ("cpu", "CPU %", 70, "e"),
            ("mem", "MEM %", 70, "e"),
            ("user", "User", 140, "w"),
            ("path", "Path / reason", 480, "w"),
        ], height=18)
        frame.pack(fill="both", expand=True)
        self.tree.tag_configure("suspicious", background="#fdecea",
                                foreground=SEV_COLORS["CRITICAL"])
        self.tree.tag_configure("normal", background="")
        self.tree.bind("<Double-1>", lambda e: self._inspect())

        self.status = tk.StringVar(value="No snapshot yet — press Refresh Now or start monitoring.")
        ttk.Label(self, textvariable=self.status).pack(anchor="w", pady=(6, 0))

    # -- data ----------------------------------------------------------------
    def refresh_now(self):
        def work():
            try:
                self.app.proc.tick()
            except Exception as exc:
                self.app.log_line(f"Process snapshot failed: {exc}")

        threading.Thread(target=work, daemon=True).start()

    def on_snapshot(self, payload):
        self.redraw()
        procs = payload.get("procs") or []
        susp = sum(1 for p in procs if p.suspicious)
        self.status.set(
            f"{len(procs)} processes | {susp} suspicious | "
            f"snapshot {ts_str(payload.get('timestamp', 0))}")

    def redraw(self):
        needle = self.filter_var.get().strip().lower()
        only_susp = self.suspicious_only.get()
        self.tree.delete(*self.tree.get_children())
        for p in getattr(self.app.proc, "latest", []) or []:
            if only_susp and not p.suspicious:
                continue
            if needle and needle not in p.name.lower() and needle not in p.exe.lower() \
                    and needle not in str(p.pid):
                continue
            display = "; ".join(p.reasons) if p.suspicious else (p.exe or "-")
            self.tree.insert("", "end", values=(
                p.pid, p.ppid, p.name, "⚠" if p.suspicious else "",
                f"{p.cpu:.1f}", f"{p.mem:.1f}", p.user or "-", display),
                tags=("suspicious" if p.suspicious else "normal",))

    # -- actions ----------------------------------------------------------------
    def _selected_pid(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return int(self.tree.item(sel[0], "values")[0])

    def _find(self, pid):
        for p in getattr(self.app.proc, "latest", []) or []:
            if p.pid == pid:
                return p
        return None

    def _inspect(self):
        pid = self._selected_pid()
        p = self._find(pid) if pid else None
        if p is None:
            messagebox.showinfo("Inspect", "Select a process first.")
            return
        win = tk.Toplevel(self)
        win.title(f"Process {p.name} (PID {p.pid})")
        win.geometry("720x420")
        text = tk.Text(win, wrap="word", font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=8, pady=8)
        started = ts_str(p.create_time) if p.create_time else "-"
        lines = [
            f"PID:        {p.pid}",
            f"PPID:       {p.ppid}  ({p.parent_name or '?'})",
            f"Name:       {p.name}",
            f"User:       {p.user or '-'}",
            f"Started:    {started}",
            f"CPU / MEM:  {p.cpu:.1f}% / {p.mem:.1f}%  "
            f"(of total RAM: {human_size(p.mem / 100 * self._total_mem())})",
            f"Image path: {p.exe or 'N/A'}",
            "",
            "Command line:",
            f"  {p.cmdline_str or '-'}",
            "",
        ]
        if p.suspicious:
            lines.append("DETECTION REASONS:")
            for r in p.reasons:
                lines.append(f"  • {r}")
        text.insert("1.0", "\n".join(lines))
        text["state"] = "disabled"

    @staticmethod
    def _total_mem() -> float:
        try:
            import psutil
            return psutil.virtual_memory().total
        except Exception:
            return 0.0

    def _kill(self):
        pid = self._selected_pid()
        if not pid:
            messagebox.showinfo("Kill", "Select a process first.")
            return
        p = self._find(pid)
        name = p.name if p else str(pid)
        if not messagebox.askyesno(
                "Kill process",
                f"Terminate {name} (PID {pid})?\n\nThis cannot be undone."):
            return
        ok = self.app.proc.kill(pid)
        self.app.log_line(("Terminated " if ok else "Failed to terminate ")
                          + f"{name} (pid {pid})")
        self.after(500, self.refresh_now)
