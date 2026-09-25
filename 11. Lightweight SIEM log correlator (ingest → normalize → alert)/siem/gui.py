"""Tkinter desktop GUI.

All widget access happens on the main thread. Live data (events, alerts, log
lines) arrives over a queue polled with ``root.after``; the pipeline threads
never touch widgets directly.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

from .events import Alert, NormalizedEvent
from .ingest import SourceConfig

WINEVT_CHANNELS = ("Application", "System", "Security", "Setup", "ForwardedEvents")
from .pipeline import Pipeline
from .rules import Rule, RULE_TYPES, SEVERITIES, safe_compile
from .storage import Storage

# ---------------------------------------------------------------------------
# presentation constants
# ---------------------------------------------------------------------------

EVENT_SEV_COLORS = {
    "CRITICAL": "#b00020",
    "ERROR": "#c62828",
    "WARNING": "#e65100",
    "DEBUG": "#757575",
}
ALERT_SEV_COLORS = {
    "critical": "#b00020",
    "high": "#c62828",
    "medium": "#e65100",
    "low": "#1565c0",
}
STATUS_COLORS = {"open": "#b00020", "acknowledged": "#e65100", "closed": "#2e7d32"}

# Demo data so a fresh install shows results in one click.
SAMPLE_LOGS = [
    # -- brute force (threshold 5/60s) --
    'Sep  7 10:00:01 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    'Sep  7 10:00:03 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    'Sep  7 10:00:05 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    'Sep  7 10:00:07 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    'Sep  7 10:00:09 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    'Sep  7 10:00:11 web sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2',
    # -- SQLi attempt --
    "10.0.0.5 - - [07/Sep/2026:10:01:00 +0000] \"GET /products.php?id=1' OR '1'='1 HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"",
    # -- web scanning: 404 flood (threshold 20/60s by src_ip) --
    *[f"10.0.0.5 - - [07/Sep/2026:10:02:{i:02d} +0000] \"GET /admin{i}.php HTTP/1.1\" 404 512 \"-\" \"-\""
      for i in range(21)],
    # -- fail-then-success (sequence) --
    'Sep  7 10:03:00 web sshd[999]: Failed password for admin from 10.0.0.9 port 22 ssh2',
    'Sep  7 10:03:30 web sshd[999]: Accepted password for admin from 10.0.0.9 port 22 ssh2',
    # -- privilege escalation --
    'Sep  7 10:04:00 web sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=localhost user=alice',
    # -- benign traffic --
    "10.0.0.5 - - [07/Sep/2026:10:05:00 +0000] \"GET /index.html HTTP/1.1\" 200 2048 \"-\" \"Mozilla/5.0\"",
    "10.0.0.5 - - [07/Sep/2026:10:05:01 +0000] \"GET /style.css HTTP/1.1\" 200 4096 \"-\" \"Mozilla/5.0\"",
    "10.0.0.5 - - [07/Sep/2026:10:05:02 +0000] \"GET /app.js HTTP/1.1\" 200 8192 \"-\" \"Mozilla/5.0\"",
    'Sep  7 10:05:03 web sshd[777]: Accepted publickey for alice from 10.0.0.9 port 22 ssh2',
]


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _tail_preview(path: str, n: int = 30, max_bytes: int = 65536) -> str:
    """Last ``n`` lines of a file for the webtail picker's preview pane."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError as exc:
        return f"(cannot read file: {exc})"
    lines = data.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return "(empty file — new lines will stream here as they arrive)"
    return "\n".join(lines[-n:])


# ---------------------------------------------------------------------------
# dialogs
# ---------------------------------------------------------------------------

class RuleDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, rule: Optional[Rule] = None,
                 on_save=None) -> None:
        super().__init__(parent)
        self.rule = rule
        self.on_save = on_save
        self.title("Edit Rule" if rule else "New Rule")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        r = 0
        self.var_name = self._row(body, r, "Name", entry=True)
        r += 1
        self.var_desc = self._row(body, r, "Description", entry=True)
        r += 1
        self.var_type = self._row(body, r, "Type", combo=True, values=RULE_TYPES)
        r += 1
        self.var_sev = self._row(body, r, "Severity", combo=True, values=SEVERITIES)
        r += 1
        self.var_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Enabled", variable=self.var_enabled) \
            .grid(row=r, column=0, columnspan=2, sticky="w", pady=(6, 0))
        r += 1
        self.var_pattern = self._row(body, r, "Pattern (regex)", entry=True)
        r += 1
        self.var_field = self._row(body, r, "Match field", entry=True)
        r += 1
        self.var_threshold = self._row(body, r, "Threshold",
                                       spin=True, lo=1, hi=100000)
        r += 1
        self.var_window = self._row(body, r, "Window (sec)", spin=True, lo=1, hi=86400)
        r += 1
        self.var_group = self._row(body, r, "Group by", entry=True)
        r += 1
        self.var_cooldown = self._row(body, r, "Cooldown (sec)", spin=True, lo=0, hi=86400)
        r += 1

        ttk.Label(body, text="Sequence steps (one per line: label | pattern)") \
            .grid(row=r, column=0, columnspan=2, sticky="w", pady=(8, 2))
        r += 1
        self.txt_steps = tk.Text(body, width=58, height=6, font=("Consolas", 9))
        self.txt_steps.grid(row=r, column=0, columnspan=2, sticky="ew")

        btns = ttk.Frame(body)
        btns.grid(row=r + 1, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="Save", command=self._save).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")

        if rule:
            self.var_name.set(rule.name)
            self.var_desc.set(rule.description)
            self.var_type.set(rule.rule_type)
            self.var_sev.set(rule.severity)
            self.var_enabled.set(rule.enabled)
            self.var_pattern.set(rule.pattern)
            self.var_field.set(rule.field)
            self.var_threshold.set(str(rule.threshold))
            self.var_window.set(str(int(rule.window)))
            self.var_group.set(rule.group_by)
            self.var_cooldown.set(str(int(rule.cooldown)))
            for st in rule.steps:
                label = st.get("label", "")
                pat = st.get("pattern", "")
                self.txt_steps.insert("end", f"{label} | {pat}\n" if label else f"{pat}\n")
        else:
            self.var_type.set("regex")
            self.var_sev.set("medium")
            self.var_field.set("message")
            self.var_threshold.set("5")
            self.var_window.set("60")
            self.var_cooldown.set("60")

    @staticmethod
    def _row(parent, row: int, label: str, entry=False, combo=False, spin=False,
             values=(), lo=0, hi=100) -> tk.Variable:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=3)
        if entry:
            var = tk.StringVar()
            ttk.Entry(parent, textvariable=var, width=46).grid(row=row, column=1, sticky="ew")
        elif combo:
            var = tk.StringVar()
            ttk.Combobox(parent, textvariable=var, values=values, state="readonly",
                         width=44).grid(row=row, column=1, sticky="ew")
        elif spin:
            var = tk.StringVar()
            ttk.Spinbox(parent, from_=lo, to=hi, textvariable=var, width=44) \
                .grid(row=row, column=1, sticky="ew")
        else:  # pragma: no cover
            var = tk.StringVar()
        return var

    def _save(self) -> None:
        name = self.var_name.get().strip()
        if not name:
            messagebox.showerror("Rule", "Name is required.", parent=self)
            return
        rule_type = self.var_type.get()
        severity = self.var_sev.get()
        if rule_type not in RULE_TYPES or severity not in SEVERITIES:
            messagebox.showerror("Rule", "Invalid type or severity.", parent=self)
            return
        pattern = self.var_pattern.get().strip()
        if rule_type in ("regex", "threshold"):
            if not pattern:
                messagebox.showerror("Rule", "A regex pattern is required.", parent=self)
                return
            if not safe_compile(pattern):
                messagebox.showerror("Rule", "Invalid regular expression.", parent=self)
                return
        steps: list[dict[str, str]] = []
        if rule_type == "sequence":
            for i, line in enumerate(self.txt_steps.get("1.0", "end").splitlines()):
                line = line.strip()
                if not line:
                    continue
                if "|" in line:
                    label, _, pat = line.partition("|")
                    label, pat = label.strip(), pat.strip()
                else:
                    label, pat = "", line
                if not safe_compile(pat):
                    messagebox.showerror("Rule", f"Step {i + 1}: invalid regex.", parent=self)
                    return
                steps.append({"label": label or f"step{i + 1}", "pattern": pat})
            if len(steps) < 2:
                messagebox.showerror("Rule", "A sequence needs at least 2 steps.", parent=self)
                return

        rule = Rule(
            id=self.rule.id if self.rule else f"rule_{int(time.time() * 1000)}",
            name=name,
            description=self.var_desc.get().strip(),
            rule_type=rule_type,
            severity=severity,
            enabled=self.var_enabled.get(),
            pattern=pattern,
            field=self.var_field.get().strip() or "message",
            threshold=int(self.var_threshold.get() or 5),
            window=float(self.var_window.get() or 60),
            group_by=self.var_group.get().strip(),
            cooldown=float(self.var_cooldown.get() or 60),
            steps=steps,
        )
        self.on_save(rule)
        self.destroy()


class SourceDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, on_save) -> None:
        super().__init__(parent)
        self.on_save = on_save
        self.title("Add Source")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Name").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        self.var_name = tk.StringVar()
        ttk.Entry(body, textvariable=self.var_name, width=40).grid(row=0, column=1)

        ttk.Label(body, text="Type").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        self.var_type = tk.StringVar(value="file")
        self.var_type.trace_add("write", lambda *_: self._on_type_change())
        ttk.Combobox(body, textvariable=self.var_type, values=("file", "udp", "winevt"),
                     state="readonly", width=38).grid(row=1, column=1)

        ttk.Label(body, text="File path").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        path_row = ttk.Frame(body)
        path_row.grid(row=2, column=1, sticky="ew")
        self.var_path = tk.StringVar()
        self._path_entry = ttk.Entry(path_row, textvariable=self.var_path, width=30)
        self._path_entry.pack(side="left")
        self._path_browse = ttk.Button(path_row, text="Browse…", command=self._browse)
        self._path_browse.pack(side="left", padx=4)

        ttk.Label(body, text="Channel (winevt)").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        self.var_channel = tk.StringVar(value="Application")
        self._channel_box = ttk.Combobox(body, textvariable=self.var_channel,
                                         values=WINEVT_CHANNELS, state="readonly",
                                         width=38)
        self._channel_box.grid(row=3, column=1)

        ttk.Label(body, text="UDP port").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        self.var_port = tk.StringVar(value="514")
        self._port_spin = ttk.Spinbox(body, from_=1, to=65535, textvariable=self.var_port,
                                      width=38)
        self._port_spin.grid(row=4, column=1)

        self.var_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Start immediately", variable=self.var_enabled) \
            .grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))

        btns = ttk.Frame(body)
        btns.grid(row=6, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="Add", command=self._save).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        self._on_type_change()

    def _on_type_change(self) -> None:
        """Show/hide the type-specific rows (webtail-style, minimal)."""
        stype = self.var_type.get()
        is_file = stype == "file"
        is_udp = stype == "udp"
        is_evt = stype == "winevt"
        # path_row children are pack-managed; port/channel rows are grid-managed
        if is_file:
            self._path_entry.pack(side="left")
            self._path_browse.pack(side="left", padx=4)
        else:
            self._path_entry.pack_forget()
            self._path_browse.pack_forget()
        if is_udp:
            self._port_spin.grid()
        else:
            self._port_spin.grid_remove()
        if is_evt:
            self._channel_box.grid()
        else:
            self._channel_box.grid_remove()

    def _browse(self) -> None:
        path = filedialog.askopenfilename(title="Select log file")
        if path:
            self.var_path.set(path)

    def _save(self) -> None:
        name = self.var_name.get().strip()
        stype = self.var_type.get()
        if not name:
            messagebox.showerror("Source", "Name is required.", parent=self)
            return
        path, port, channel = "", 514, "Application"
        if stype == "udp":
            try:
                port = int(self.var_port.get())
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Source", "Port must be 1-65535.", parent=self)
                return
        elif stype == "winevt":
            channel = self.var_channel.get().strip() or "Application"
        else:
            path = self.var_path.get().strip()
            if not path:
                messagebox.showerror("Source", "A file path is required.", parent=self)
                return
        cfg = SourceConfig(
            id=f"src_{int(time.time() * 1000)}",
            name=name, type=stype, path=path, port=port,
            enabled=self.var_enabled.get(), channel=channel,
        )
        self.on_save(cfg)
        self.destroy()


class TailDialog(tk.Toplevel):
    """Webtail-style file picker: pick a log file, preview its tail, stream it live.

    Unlike the plain Add-Source dialog this shows the end of the chosen file
    (like a webtail UI) before you commit, and defaults to follow-only-new-lines
    so you watch the file grow instead of replaying history.
    """

    def __init__(self, parent: tk.Widget, on_start, existing_names=()) -> None:
        super().__init__(parent)
        self.on_start = on_start
        self.existing_names = set(existing_names)
        self.title("Tail a log file")
        self.geometry("680x480")
        self.resizable(True, True)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Log file").pack(anchor="w")
        path_row = ttk.Frame(body)
        path_row.pack(fill="x", pady=(2, 6))
        self.var_path = tk.StringVar()
        self.var_path.trace_add("write", lambda *_: self._update_preview())
        ttk.Entry(path_row, textvariable=self.var_path).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="Browse…", command=self._browse).pack(side="left", padx=(6, 0))

        opts = ttk.Frame(body)
        opts.pack(fill="x", pady=(0, 6))
        self.var_follow = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Follow only new lines (start at end of file)",
                        variable=self.var_follow).pack(side="left")
        ttk.Label(opts, text="  uncheck to ingest existing content too",
                  foreground="#666666").pack(side="left")

        ttk.Label(body, text="Preview (last lines)").pack(anchor="w")
        self._preview = tk.Text(body, height=14, state="disabled", font=("Consolas", 9),
                                bg="#f5f5f5", fg="#222222")
        self._preview.pack(fill="both", expand=True, pady=(2, 6))
        self._status = tk.StringVar(value="Choose a file to preview its tail.")
        ttk.Label(body, textvariable=self._status, foreground="#666666") \
            .pack(anchor="w", pady=(0, 6))

        btns = ttk.Frame(body)
        btns.pack(fill="x")
        ttk.Button(btns, text="Start tailing", command=self._start).pack(side="right", padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Pick a log file to tail",
            filetypes=(("Log files", "*.log *.txt *.out"), ("All files", "*.*")),
        )
        if path:
            self.var_path.set(path)

    def _update_preview(self) -> None:
        path = self.var_path.get().strip()
        self._preview.config(state="normal")
        self._preview.delete("1.0", "end")
        if not path:
            self._status.set("Choose a file to preview its tail.")
        else:
            self._preview.insert("1.0", _tail_preview(path))
            try:
                size = os.path.getsize(path)
                self._status.set(f"{path}  —  {size:,} bytes")
            except OSError:
                self._status.set(f"{path}  —  cannot stat")
        self._preview.config(state="disabled")

    def _start(self) -> None:
        path = self.var_path.get().strip()
        if not path:
            messagebox.showerror("Tail file", "Choose a log file first.", parent=self)
            return
        if not os.path.isfile(path):
            messagebox.showerror("Tail file", f"File not found:\n{path}", parent=self)
            return
        base = os.path.basename(path) or "tail"
        name = base
        n = 2
        while name in self.existing_names:
            name = f"{base} ({n})"
            n += 1
        cfg = SourceConfig(
            id=f"src_{int(time.time() * 1000)}",
            name=name, type="file", path=path,
            start_at_end=self.var_follow.get(), enabled=True,
        )
        self.on_start(cfg)
        self.destroy()


class TextDialog(tk.Toplevel):
    """Generic multiline input (paste logs) or read-only detail view."""

    def __init__(self, parent: tk.Widget, title: str, initial: str = "",
                 readonly: bool = False, ok_label: str = "OK") -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("640x380")
        self.transient(parent.winfo_toplevel())
        self.grab_set()
        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)
        self.txt = tk.Text(body, wrap="word", font=("Consolas", 9))
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("1.0", initial)
        if readonly:
            self.txt.config(state="disabled")
        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(8, 0))
        if not readonly:
            ttk.Button(btns, text=ok_label, command=self._ok).pack(side="right", padx=4)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")

    def _ok(self) -> None:
        self.result = self.txt.get("1.0", "end")
        self.destroy()

    def get_text(self) -> str:
        return getattr(self, "result", "")


# ---------------------------------------------------------------------------
# main application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, pipeline: Pipeline, storage: Storage, config: dict[str, Any]) -> None:
        super().__init__()
        self.pipeline = pipeline
        self.storage = storage
        self.config = config

        self.title("SIEM Log Correlator")
        self.geometry("1200x740")
        self.minsize(900, 560)

        self._ui_q: "queue.Queue[tuple]" = queue.Queue()
        self._rate_ts: list[float] = []
        self._alert_pending = False

        # Route pipeline callbacks into the UI queue (never call widgets directly).
        self.pipeline.on_event = lambda ev: self._ui_q.put(("event", ev))
        self.pipeline.on_alert = lambda al: self._ui_q.put(("alert", al))
        self.pipeline.on_log = lambda line: self._ui_q.put(("log", line))

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(150, self._poll)
        self.after(1000, self._refresh_dashboard)

    # ---------------------------------------------------------------- UI build
    def _build_ui(self) -> None:
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True)
        self._build_dashboard()
        self._build_events()
        self._build_alerts()
        self._build_rules()
        self._build_sources()
        self._build_console()
        self._nb.bind("<<NotebookTabChanged>>", lambda _e: self._refresh_active_tab())

    # -------------------------------------------------------------- dashboard
    def _build_dashboard(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Dashboard")

        stats = ttk.LabelFrame(tab, text="Statistics", padding=10)
        stats.pack(fill="x", pady=(0, 8))
        self._stat_vars: dict[str, tk.StringVar] = {}
        names = [
            ("events", "Events total"), ("rate", "Events / min"),
            ("open", "Open alerts"), ("sources", "Active sources"),
            ("rules", "Rules enabled"), ("norm", "Normalized (dropped)"),
        ]
        for i, (key, caption) in enumerate(names):
            cell = ttk.Frame(stats)
            cell.grid(row=0, column=i, padx=16, pady=4)
            var = tk.StringVar(value="0")
            self._stat_vars[key] = var
            ttk.Label(cell, textvariable=var, font=("Segoe UI", 16, "bold")) \
                .pack()
            ttk.Label(cell, text=caption, font=("Segoe UI", 8)) \
                .pack()

        chart = ttk.LabelFrame(tab, text="Alerts (last 24 h) by severity", padding=6)
        chart.pack(fill="both", expand=True)
        self._chart = tk.Canvas(chart, height=170, bg="white", highlightthickness=1,
                                highlightbackground="#cccccc")
        self._chart.pack(fill="both", expand=True)
        self._chart_legend = ttk.Label(chart, text="", font=("Segoe UI", 8))
        self._chart_legend.pack(fill="x")

        console_frame = ttk.LabelFrame(tab, text="Engine log", padding=6)
        console_frame.pack(fill="both", expand=True, pady=(8, 0))
        self._mini_log = tk.Text(console_frame, height=8, state="disabled",
                                 font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self._mini_log.pack(fill="both", expand=True)

    def _refresh_dashboard(self) -> None:
        try:
            stats = self.storage.stats()
            now = time.time()
            self._rate_ts = [t for t in self._rate_ts if now - t <= 60]
            s = self.pipeline.stats
            self._stat_vars["events"].set(f"{stats['total_events']:,}")
            self._stat_vars["rate"].set(str(len(self._rate_ts)))
            self._stat_vars["open"].set(str(stats["open_alerts"]))
            self._stat_vars["sources"].set(
                str(sum(1 for st in self.pipeline.sources.statuses().values()
                        if st not in ("stopped", "missing file")
                        and not st.startswith("requires")))
            )
            self._stat_vars["rules"].set(str(stats["enabled_rules"]))
            self._stat_vars["norm"].set(f"{s['normalized']:,} ({s['dropped']:,})")
            self._draw_chart(stats.get("alerts_24h", {}))
        except Exception:
            pass
        self.after(1000, self._refresh_dashboard)

    def _draw_chart(self, counts: dict[str, int]) -> None:
        c = self._chart
        c.delete("all")
        w = max(c.winfo_width(), 200)
        h = max(c.winfo_height(), 100)
        order = ["critical", "high", "medium", "low"]
        total = sum(counts.values())
        if total == 0:
            c.create_text(w // 2, h // 2, text="No alerts in the last 24 h",
                          fill="#888888")
            self._chart_legend.config(text="")
            return
        bar_w = max(40, min(90, (w - 80) // len(order)))
        gap = 30
        base = h - 30
        max_v = max(counts.get(s, 0) for s in order) or 1
        x = 30
        for sev in order:
            v = counts.get(sev, 0)
            bh = max(4, int((v / max_v) * (h - 70)))
            color = ALERT_SEV_COLORS.get(sev, "#888888")
            c.create_rectangle(x, base - bh, x + bar_w, base, fill=color, outline="")
            c.create_text(x + bar_w // 2, base - bh - 10, text=str(v),
                          font=("Segoe UI", 9, "bold"))
            c.create_text(x + bar_w // 2, base + 12, text=sev.capitalize(),
                          font=("Segoe UI", 8))
            x += bar_w + gap
        self._chart_legend.config(text=f"{total:,} alert(s) total")

    # ----------------------------------------------------------------- events
    def _build_events(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Live Events")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Filter:").pack(side="left")
        self._ev_filter = tk.StringVar()
        ttk.Entry(bar, textvariable=self._ev_filter, width=30).pack(side="left", padx=6)
        self._ev_scroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Newest first", variable=self._ev_scroll) \
            .pack(side="left", padx=6)
        ttk.Button(bar, text="Clear", command=self._clear_events).pack(side="left", padx=6)
        ttk.Button(bar, text="Paste logs…", command=self._paste_logs).pack(side="left", padx=6)
        ttk.Button(bar, text="Tail file…", command=self._tail_file).pack(side="left", padx=6)
        ttk.Button(bar, text="Load sample logs", command=self._load_sample).pack(side="left", padx=6)

        cols = ("time", "source", "host", "severity", "message")
        self._ev_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width, anchor in (
            ("time", 150, "w"), ("source", 110, "w"), ("host", 110, "w"),
            ("severity", 80, "center"), ("message", 640, "w"),
        ):
            self._ev_tree.heading(col, text=col.title())
            self._ev_tree.column(col, width=width, anchor=anchor, stretch=(col == "message"))
        for sev, color in EVENT_SEV_COLORS.items():
            self._ev_tree.tag_configure(sev.lower(), foreground=color)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self._ev_tree.yview)
        self._ev_tree.configure(yscrollcommand=vsb.set)
        self._ev_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _clear_events(self) -> None:
        self._ev_tree.delete(*self._ev_tree.get_children())

    def _paste_logs(self) -> None:
        dlg = TextDialog(self, "Paste log lines", ok_label="Ingest")
        self.wait_window(dlg)
        text = dlg.get_text().strip()
        if text:
            self.pipeline.ingest_text(text)

    def _load_sample(self) -> None:
        self.pipeline.ingest_text("\n".join(SAMPLE_LOGS), "sample")

    # ----------------------------------------------------------------- alerts
    def _build_alerts(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Alerts")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Acknowledge", command=lambda: self._set_status("acknowledged")) \
            .pack(side="left", padx=3)
        ttk.Button(bar, text="Close", command=lambda: self._set_status("closed")) \
            .pack(side="left", padx=3)
        ttk.Button(bar, text="Reopen", command=lambda: self._set_status("open")) \
            .pack(side="left", padx=3)
        ttk.Button(bar, text="Details…", command=self._alert_details).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh", command=self._reload_alerts).pack(side="left", padx=3)

        cols = ("id", "time", "severity", "rule", "summary", "status")
        self._al_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width, anchor in (
            ("id", 50, "center"), ("time", 140, "w"), ("severity", 70, "center"),
            ("rule", 180, "w"), ("summary", 520, "w"), ("status", 100, "center"),
        ):
            self._al_tree.heading(col, text=col.title())
            self._al_tree.column(col, width=width, anchor=anchor, stretch=(col == "summary"))
        for sev, color in ALERT_SEV_COLORS.items():
            self._al_tree.tag_configure(sev, foreground=color)
        for status, color in STATUS_COLORS.items():
            self._al_tree.tag_configure(status, foreground=color)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self._al_tree.yview)
        self._al_tree.configure(yscrollcommand=vsb.set)
        self._al_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._reload_alerts()

    def _selected_alert_id(self) -> Optional[int]:
        sel = self._al_tree.selection()
        if not sel:
            return None
        return int(self._al_tree.item(sel[0], "values")[0])

    def _set_status(self, status: str) -> None:
        aid = self._selected_alert_id()
        if aid is None:
            return
        self.storage.set_alert_status(aid, status)
        self._reload_alerts()

    def _alert_details(self) -> None:
        sel = self._al_tree.selection()
        if not sel:
            return
        values = self._al_tree.item(sel[0], "values")
        alert_id = int(values[0])
        alert = next((a for a in self.storage.get_alerts(500) if a.id == alert_id), None)
        if alert is None:
            return
        body = (
            f"ID        : {alert.id}\n"
            f"Time      : {alert.display_time()}\n"
            f"Rule      : {alert.rule_name} ({alert.rule_id})\n"
            f"Severity  : {alert.severity}\n"
            f"Group key : {alert.group_key}\n"
            f"Count     : {alert.count}\n"
            f"Status    : {alert.status}\n\n"
            f"Summary   : {alert.summary}\n\n"
            f"Fields    :\n{json.dumps(alert.fields, indent=2, default=str)}"
        )
        TextDialog(self, "Alert details", initial=body, readonly=True)

    def _reload_alerts(self) -> None:
        self._al_tree.delete(*self._al_tree.get_children())
        for a in self.storage.get_alerts(int(self.config.get("max_alerts_rows", 500))):
            self._al_tree.insert(
                "", "end",
                values=(a.id, a.display_time(), a.severity, a.rule_name,
                        a.summary, a.status),
                tags=(a.severity, a.status),
            )

    # ------------------------------------------------------------------ rules
    def _build_rules(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Rules")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="New…", command=self._new_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Edit…", command=self._edit_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Enable/Disable", command=self._toggle_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Delete", command=self._delete_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh", command=self._reload_rules).pack(side="left", padx=3)
        ttk.Label(bar, text="  (changes hot-reload the engine)").pack(side="left")

        cols = ("name", "type", "severity", "enabled", "description")
        self._ru_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width in (("name", 190), ("type", 80), ("severity", 80),
                           ("enabled", 60), ("description", 560)):
            self._ru_tree.heading(col, text=col.title())
            self._ru_tree.column(col, width=width, stretch=(col == "description"))
        for sev, color in ALERT_SEV_COLORS.items():
            self._ru_tree.tag_configure(sev, foreground=color)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self._ru_tree.yview)
        self._ru_tree.configure(yscrollcommand=vsb.set)
        self._ru_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._reload_rules()

    def _selected_rule_id(self) -> Optional[str]:
        sel = self._ru_tree.selection()
        return self._ru_tree.item(sel[0], "values")[0] if sel else None

    def _reload_rules(self) -> None:
        self._ru_tree.delete(*self._ru_tree.get_children())
        for r in self.storage.get_rules():
            self._ru_tree.insert(
                "", "end",
                values=(r.name, r.rule_type, r.severity,
                        "yes" if r.enabled else "no", r.description),
                tags=(r.severity,),
            )

    def _new_rule(self) -> None:
        RuleDialog(self, rule=None, on_save=self._save_rule)

    def _edit_rule(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        rule = next((r for r in self.storage.get_rules() if r.id == rid), None)
        if rule:
            RuleDialog(self, rule=rule, on_save=self._save_rule)

    def _save_rule(self, rule: Rule) -> None:
        self.storage.save_rule(rule)
        self.pipeline.reload_rules()
        self._reload_rules()

    def _toggle_rule(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        rule = next((r for r in self.storage.get_rules() if r.id == rid), None)
        if rule:
            rule.enabled = not rule.enabled
            self.storage.save_rule(rule)
            self.pipeline.reload_rules()
            self._reload_rules()

    def _delete_rule(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        if not messagebox.askyesno("Rules", "Delete this rule?", parent=self):
            return
        self.storage.delete_rule(rid)
        self.pipeline.reload_rules()
        self._reload_rules()

    # ---------------------------------------------------------------- sources
    def _build_sources(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Sources")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Tail file…", command=self._tail_file).pack(side="left", padx=3)
        ttk.Button(bar, text="Add…", command=self._add_source).pack(side="left", padx=3)
        ttk.Button(bar, text="Remove", command=self._remove_source).pack(side="left", padx=3)
        ttk.Button(bar, text="Start", command=self._start_source).pack(side="left", padx=3)
        ttk.Button(bar, text="Stop", command=self._stop_source).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh", command=self._reload_sources).pack(side="left", padx=3)

        cols = ("name", "type", "detail", "status")
        self._so_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width in (("name", 160), ("type", 60), ("detail", 420), ("status", 140)):
            self._so_tree.heading(col, text=col.title())
            self._so_tree.column(col, width=width, stretch=(col == "detail"))
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self._so_tree.yview)
        self._so_tree.configure(yscrollcommand=vsb.set)
        self._so_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        hint = ttk.Label(tab, text=(
            "Tip: \"Tail file…\" watches a log live (webtail-style). UDP sources "
            "listen for raw syslog datagrams; \"Windows Event Log\" sources read "
            "a channel via wevtutil (tail-only, needs Windows)."
        ), foreground="#666666")
        hint.pack(side="bottom", fill="x", pady=4)
        self._reload_sources()
        self.after(1000, self._tick_sources)

    def _reload_sources(self) -> None:
        self._so_tree.delete(*self._so_tree.get_children())
        statuses = self.pipeline.sources.statuses()
        for s in self.pipeline.sources.sources():
            self._so_tree.insert("", "end", values=(
                s.name, s.type, s.describe(), statuses.get(s.id, "unknown"),
            ))

    def _tick_sources(self) -> None:
        if self.winfo_exists():
            self._reload_sources()
            self.after(1000, self._tick_sources)

    def _selected_source_id(self) -> Optional[str]:
        sel = self._so_tree.selection()
        if not sel:
            return None
        name = self._so_tree.item(sel[0], "values")[0]
        for s in self.pipeline.sources.sources():
            if s.name == name:
                return s.id
        return None

    def _add_source(self) -> None:
        SourceDialog(self, on_save=self.pipeline.add_source)

    def _tail_file(self) -> None:
        existing = [s.name for s in self.pipeline.sources.sources()]
        TailDialog(self, on_start=self.pipeline.add_source, existing_names=existing)

    def _remove_source(self) -> None:
        sid = self._selected_source_id()
        if sid is not None:
            self.pipeline.remove_source(sid)
            self._reload_sources()

    def _start_source(self) -> None:
        sid = self._selected_source_id()
        if sid is not None:
            self.pipeline.start_source(sid)
            self._reload_sources()

    def _stop_source(self) -> None:
        sid = self._selected_source_id()
        if sid is not None:
            self.pipeline.stop_source(sid)
            self._reload_sources()

    # ----------------------------------------------------------------- console
    def _build_console(self) -> None:
        tab = ttk.Frame(self._nb, padding=8)
        self._nb.add(tab, text="Console")
        self._console = tk.Text(tab, state="disabled", wrap="none",
                                font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self._console.pack(fill="both", expand=True)
        self._console.tag_configure("alert", foreground="#ff9d9d")
        self._console.tag_configure("info", foreground="#9cdcfe")
        self._console_lines = 0
        self._append_log(f"{_now_str()}  SIEM Log Correlator started")

    def _append_log(self, line: str) -> None:
        self._console.config(state="normal")
        tag = "alert" if "[ALERT]" in line else ("info" if "started" in line or "stopped" in line else "")
        self._console.insert("end", line + "\n", tag)
        self._console_lines += 1
        if self._console_lines > 1000:
            excess = self._console_lines - 1000
            self._console.delete("1.0", f"1.0+{excess}l")
            self._console_lines = 1000
        self._console.see("end")
        self._console.config(state="disabled")
        # Mirror into the dashboard mini log (kept shorter).
        try:
            self._mini_log.config(state="normal")
            self._mini_log.insert("end", line + "\n", tag)
            while int(self._mini_log.index("end-1c").split(".")[0]) > 60:
                self._mini_log.delete("1.0", "2.0")
            self._mini_log.see("end")
            self._mini_log.config(state="disabled")
        except Exception:
            pass

    # --------------------------------------------------------------- polling
    def _poll(self) -> None:
        drained = 0
        while drained < 300 and not self._ui_q.empty():
            item = self._ui_q.get_nowait()
            try:
                kind = item[0]
                if kind == "event":
                    self._on_ui_event(item[1])
                elif kind == "alert":
                    self._on_ui_alert(item[1])
                elif kind == "log":
                    self._append_log(item[1])
            except Exception:
                pass
            drained += 1
        self.after(150, self._poll)

    def _on_ui_event(self, ev: NormalizedEvent) -> None:
        self._rate_ts.append(ev.ts)
        filt = self._ev_filter.get().strip().lower()
        if filt and filt not in ev.message.lower() and filt not in ev.host.lower() \
                and filt not in ev.source.lower():
            return
        max_rows = int(self.config.get("max_events_rows", 5000))
        self._ev_tree.insert(
            "", 0 if self._ev_scroll.get() else "end",
            values=(ev.display_time(), ev.source, ev.host, ev.severity,
                    ev.message[:300]),
            tags=(ev.severity.lower(),),
        )
        if len(self._ev_tree.get_children()) > max_rows:
            kids = self._ev_tree.get_children()
            self._ev_tree.delete(*kids[max_rows:])

    def _on_ui_alert(self, alert: Alert) -> None:
        max_rows = int(self.config.get("max_alerts_rows", 500))
        self._al_tree.insert(
            "", 0,
            values=(alert.id, alert.display_time(), alert.severity,
                    alert.rule_name, alert.summary, alert.status),
            tags=(alert.severity, alert.status),
        )
        if len(self._al_tree.get_children()) > max_rows:
            kids = self._al_tree.get_children()
            self._al_tree.delete(*kids[max_rows:])
        self._flash_alerts_tab()
        if self.config.get("alert_beep", True):
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except Exception:
                pass

    def _flash_alerts_tab(self) -> None:
        if self._alert_pending:
            return
        self._alert_pending = True
        self._nb.tab(2, text="Alerts ⚑")
        self.after(4000, lambda: (self._nb.tab(2, text="Alerts"),
                                  setattr(self, "_alert_pending", False)))

    def _refresh_active_tab(self) -> None:
        try:
            idx = self._nb.index(self._nb.select())
            if idx == 2:
                self._reload_alerts()
            elif idx == 3:
                self._reload_rules()
            elif idx == 4:
                self._reload_sources()
        except Exception:
            pass

    # ----------------------------------------------------------------- close
    def _on_close(self) -> None:
        try:
            self.pipeline.stop()
        except Exception:
            pass
        try:
            self.storage.close()
        except Exception:
            pass
        self.destroy()