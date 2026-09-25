"""Tkinter GUI for the Agent Check-in Jitter/Sleep Study.

Threading rule: engine threads never touch Tk. Events flow through a
queue.Queue, drained by the Tk main loop every POLL_MS.
"""
from __future__ import annotations

import queue
import os
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, List, Optional

from core.config import (AppConfig, CheckinProfile, ServerConfig,
                         STRATEGIES, STRATEGY_LABELS)
from core.fleet import Fleet
from persistence.state import StateStore
from persistence.memory import MemoryStore

POLL_MS = 100
CHART_DEBOUNCE_MS = 1000
RING_LIMIT = 10000


class ProfileForm(ttk.LabelFrame):
    """Editor for one CheckinProfile; validates on read."""

    def __init__(self, master, profile: Optional[CheckinProfile] = None) -> None:
        super().__init__(master, text="Profile")
        p = profile or CheckinProfile()
        self.vars: Dict[str, tk.StringVar] = {}

        def add(row: int, label: str, key: str, value) -> None:
            lbl = ttk.Label(self, text=label)
            lbl.grid(row=row, column=0, sticky="e", padx=4, pady=2)
            var = tk.StringVar(value=str(value))
            ent = ttk.Entry(self, textvariable=var, width=14)
            ent.grid(row=row, column=1, sticky="w", padx=4, pady=2)
            self.vars[key] = var

        r = 0
        add(r, "Name", "name", p.name); r += 1
        ttk.Label(self, text="Strategy").grid(row=r, column=0, sticky="e", padx=4, pady=2)
        self.strategy_var = tk.StringVar(value=p.strategy)
        cb = ttk.Combobox(self, textvariable=self.strategy_var, state="readonly",
                          values=list(STRATEGIES), width=12)
        cb.grid(row=r, column=1, sticky="w", padx=4, pady=2)
        r += 1
        add(r, "Base delay (s)", "base_delay_s", p.base_delay_s); r += 1
        add(r, "Jitter (s)", "jitter_s", p.jitter_s); r += 1
        add(r, "Cap (s)", "cap_s", p.cap_s); r += 1
        add(r, "Multiplier", "multiplier", p.multiplier); r += 1
        add(r, "Startup spread (s)", "startup_spread_s", p.startup_spread_s); r += 1
        add(r, "Agent count", "agent_count", p.agent_count); r += 1
        add(r, "Seed", "seed", p.seed); r += 1

    def read(self) -> CheckinProfile:
        """Read form into a CheckinProfile; raises ValueError on bad numbers."""
        def num(key: str, cast=float):
            return cast(float(self.vars[key].get()))

        return CheckinProfile(
            name=self.vars["name"].get().strip(),
            strategy=self.strategy_var.get(),
            base_delay_s=num("base_delay_s"),
            jitter_s=num("jitter_s"),
            cap_s=num("cap_s"),
            multiplier=num("multiplier"),
            startup_spread_s=num("startup_spread_s"),
            agent_count=num("agent_count", int),
            seed=num("seed", int),
        )


class ServerForm(ttk.LabelFrame):
    """Editor for ServerConfig."""

    def __init__(self, master, cfg: Optional[ServerConfig] = None) -> None:
        super().__init__(master, text="Simulated server")
        c = cfg or ServerConfig()
        self.failure_rate = tk.StringVar(value=str(c.failure_rate))
        self.latency_min_ms = tk.StringVar(value=str(c.latency_min_ms))
        self.latency_max_ms = tk.StringVar(value=str(c.latency_max_ms))
        self.lockout_after_failures = tk.StringVar(value=str(c.lockout_after_failures))
        self.lockout_duration_s = tk.StringVar(value=str(c.lockout_duration_s))
        self.bucket_s = tk.StringVar(value=str(c.bucket_s))

        rows = [("Failure rate (0-1)", self.failure_rate),
                ("Latency min (ms)", self.latency_min_ms),
                ("Latency max (ms)", self.latency_max_ms),
                ("Lockout after N fails", self.lockout_after_failures),
                ("Lockout duration (s)", self.lockout_duration_s),
                ("Load bucket (s)", self.bucket_s)]
        for i, (label, var) in enumerate(rows):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="e", padx=4, pady=2)
            ttk.Entry(self, textvariable=var, width=12).grid(row=i, column=1,
                                                             sticky="w", padx=4, pady=2)

    def read(self) -> ServerConfig:
        return ServerConfig(
            failure_rate=float(self.failure_rate.get()),
            latency_min_ms=int(self.latency_min_ms.get()),
            latency_max_ms=int(self.latency_max_ms.get()),
            lockout_after_failures=int(self.lockout_after_failures.get()),
            lockout_duration_s=float(self.lockout_duration_s.get()),
            bucket_s=float(self.bucket_s.get()),
        )


class App(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Agent Check-in Jitter/Sleep Study Lab")
        self.geometry("1250x780")
        self.minsize(1000, 620)

        self.root_dir = "."
        self.state_store = StateStore(self.root_dir)
        self.memory_store = MemoryStore(self.root_dir)
        self.memory_store.ensure_notes_section()

        self.fleet: Optional[Fleet] = None
        self.event_queue: "queue.Queue[Dict]" = queue.Queue()
        self.ring: List[Dict] = []
        self.ring_pos = 0
        self.paused = False
        self.log_paused = False
        self._last_chart_render = 0.0
        self._chart_dirty = False

        self._build_ui()
        self._poll_queue()

    # ------------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        self._build_menu()
        self._build_toolbar()
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned, width=340)
        right = ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=3)

        self._build_left_panel(left)
        self._build_tabs(right)
        self._build_statusbar()

    def _build_menu(self) -> None:
        """File menu — 'Export CSV As…' lets the user choose name/location."""
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export CSV As…",
                              command=self.on_export_csv_as,
                              accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        self.configure(menu=menubar)
        self.bind("<Control-e>", lambda e: self.on_export_csv_as())

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=4)
        bar.pack(side="top", fill="x")
        self.start_btn = ttk.Button(bar, text="▶ Start", command=self.on_start)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(bar, text="■ Stop", command=self.on_stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(bar, text="💾 Save state", command=self.on_save_state).pack(side="left", padx=2)
        ttk.Button(bar, text="📄 Export JSON", command=self.on_export).pack(side="left", padx=2)
        ttk.Button(bar, text="📊 Export CSV", command=self.on_export_csv).pack(side="left", padx=2)
        ttk.Button(bar, text="Load state", command=self.on_load_state).pack(side="left", padx=2)

        ttk.Label(bar, text="Speed:").pack(side="left", padx=(14, 2))
        self.speed_var = tk.StringVar(value="1.0")
        speed = ttk.Combobox(bar, textvariable=self.speed_var, state="readonly",
                             values=["0.1", "1.0", "10.0", "100.0"], width=5)
        speed.pack(side="left")
        ttk.Label(bar, text="Duration (s, 0=∞):").pack(side="left", padx=(14, 2))
        self.duration_var = tk.StringVar(value="0")
        ttk.Entry(bar, textvariable=self.duration_var, width=7).pack(side="left")
        ttk.Label(bar, text="Seed:").pack(side="left", padx=(14, 2))
        self.seed_var = tk.StringVar(value="1234")
        ttk.Entry(bar, textvariable=self.seed_var, width=8).pack(side="left")

        self.log_pause_btn = ttk.Button(bar, text="⏸ Pause log",
                                        command=self.on_toggle_log_pause)
        self.log_pause_btn.pack(side="right", padx=2)

    def _build_left_panel(self, parent) -> None:
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)

        # --- profiles
        self.profile_forms_parent = ttk.LabelFrame(wrap, text="Profiles", padding=4)
        self.profile_forms_parent.pack(fill="x")
        self.profile_forms: List[ProfileForm] = []
        self._new_profile_form(self.profile_forms_parent)

        ttk.Button(self.profile_forms_parent, text="+ Add profile",
                   command=lambda: self._new_profile_form(self.profile_forms_parent)).grid(
            row=99, column=0, columnspan=2, sticky="w", padx=4, pady=4)

        # --- server settings
        self.server_form = ServerForm(wrap)
        self.server_form.pack(fill="x", pady=(8, 0))

        # --- run info / help
        help_box = ttk.LabelFrame(wrap, text="Strategy notes", padding=6)
        help_box.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Label(help_box, justify="left", text=(
            "fixed          — deterministic; herd demo\n"
            "uniform        — base + U(0, jitter)\n"
            "decorrelated   — U(base, min(cap, prev×m))\n"
            "equal          — base/2 + U(0, jitter)\n"
            "\n"
            "Drift = actual − scheduled arrival.\n"
            "All randomness is seeded: same seed\n"
            "+ same config ⇒ identical run."
        )).pack(anchor="w")

    def _new_profile_form(self, parent) -> None:
        idx = len(self.profile_forms)
        f = ProfileForm(parent, CheckinProfile(
            name=f"profile-{idx + 1}",
            strategy=["uniform", "fixed", "decorrelated", "equal"][idx % 4],
            seed=42 + idx * 100,
        ))
        f.grid(row=idx * 2, column=0, columnspan=2, sticky="we", padx=2, pady=3)
        rm = ttk.Button(parent, text=f"✕ Remove {f.vars['name'].get() or 'profile'}",
                        command=lambda: self._remove_profile_form(f, rm))
        rm.grid(row=idx * 2 + 1, column=0, columnspan=2, sticky="w", padx=4)
        self.profile_forms.append(f)

    def _remove_profile_form(self, form, btn) -> None:
        if not self.profile_forms:
            return
        form.destroy()
        btn.destroy()
        self.profile_forms.remove(form)

    # ----------------------------------------------------------------- tabs
    def _build_tabs(self, parent) -> None:
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True)

        # --- live log tab
        log_tab = ttk.Frame(self.nb)
        self.nb.add(log_tab, text="Live log")
        self.log_text = tk.Text(log_tab, height=10, state="disabled",
                                font=("Consolas", 9), wrap="none")
        ysb = ttk.Scrollbar(log_tab, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=ysb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        for tag, color in (("ok", "#0a7d32"), ("fail", "#b3261e"),
                           ("info", "#555555"), ("warn", "#9a6700")):
            self.log_text.tag_configure(tag, foreground=color)
        self.log_line_count = 0

        # --- metrics tab
        met_tab = ttk.Frame(self.nb)
        self.nb.add(met_tab, text="Metrics")
        cols = ("profile", "agents", "checkins", "successes", "failures", "retries",
                "interval_mean_s", "interval_std_s", "drift_p50_s",
                "drift_p95_s", "drift_max_s")
        self.metrics_tree = ttk.Treeview(met_tab, columns=cols, show="headings", height=14)
        widths = {"profile": 140, "agents": 60, "checkins": 80, "successes": 80,
                  "failures": 70, "retries": 70, "interval_mean_s": 110,
                  "interval_std_s": 110, "drift_p50_s": 90, "drift_p95_s": 90,
                  "drift_max_s": 90}
        for c in cols:
            self.metrics_tree.heading(c, text=c)
            self.metrics_tree.column(c, width=widths[c], anchor="e" if c != "profile" else "w")
        ysb = ttk.Scrollbar(met_tab, orient="vertical", command=self.metrics_tree.yview)
        self.metrics_tree.configure(yscrollcommand=ysb.set)
        self.metrics_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

        # --- charts tab
        chart_tab = ttk.Frame(self.nb)
        self.nb.add(chart_tab, text="Charts")
        self._build_charts(chart_tab)

    def _build_charts(self, parent) -> None:
        try:
            import matplotlib
            matplotlib.use("TkAgg")
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
        except Exception as e:  # matplotlib optional at runtime
            ttk.Label(parent, text=f"matplotlib unavailable ({e}); charts disabled.",
                      foreground="#b3261e").pack(padx=10, pady=10)
            self.chart_canvas = None
            return

        self.fig = Figure(figsize=(11.5, 7.2), dpi=96)
        self.ax_arr = self.fig.add_subplot(3, 1, 1)
        self.ax_drift = self.fig.add_subplot(3, 1, 2)
        self.ax_int = self.fig.add_subplot(3, 1, 3)
        self.fig.tight_layout(pad=2.5)

        self.chart_canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)

    # ------------------------------------------------------------ status bar
    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, relief="sunken", padding=(6, 2))
        bar.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Idle — configure profiles and press Start")
        ttk.Label(bar, textvariable=self.status_var, anchor="w").pack(side="left", fill="x", expand=True)
        self.clock_var = tk.StringVar(value="sim t=0.0s")
        ttk.Label(bar, textvariable=self.clock_var).pack(side="right")

    # ------------------------------------------------------------- handlers
    def read_config(self) -> AppConfig:
        profiles = [f.read() for f in self.profile_forms]
        server = self.server_form.read() if hasattr(self, "server_form") else ServerConfig()
        return AppConfig(profiles=profiles, server=server,
                         seed=int(float(self.seed_var.get())),
                         duration_s=float(self.duration_var.get()),
                         speed=float(self.speed_var.get()))

    def on_start(self) -> None:
        try:
            config = self.read_config()
        except (ValueError, tk.TclError) as e:
            messagebox.showerror("Invalid input", f"Please check numeric fields:\n{e}")
            return
        errs = config.validate()
        if errs:
            messagebox.showerror("Invalid configuration", "\n".join(errs))
            return

        self.event_queue = queue.Queue()
        self.ring.clear()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.log_line_count = 0

        self.fleet = Fleet(config, sink=lambda ev: self.event_queue.put(ev))
        self.fleet.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set(f"Running — fingerprint {config.fingerprint()}"
                            f" ({len(self.fleet.agents)} agents)")

    def on_stop(self) -> None:
        if self.fleet:
            self.status_var.set("Stopping…")
            self.fleet.stop()
            summary = self.fleet.summary()
            self.memory_store.append_run(self.fleet.config, summary,
                                         events=self.fleet.events())
            self._render_metrics(summary)
            self.status_var.set(
                f"Stopped — {summary['server']['total']} check-ins recorded; "
                f"run appended to memory.md")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def on_save_state(self) -> None:
        if not self.fleet:
            # allow saving the configured (not-yet-run) state too
            try:
                config = self.read_config()
            except (ValueError, tk.TclError) as e:
                messagebox.showerror("Invalid input", str(e))
                return
            errs = config.validate()
            if errs:
                messagebox.showerror("Invalid configuration", "\n".join(errs))
                return
            self.state_store.save(config, {"elapsed_sim_s": 0.0, "agents": 0,
                                           "profiles": {}, "server": {}}, 0,
                                  note="saved before any run")
            self.status_var.set("State saved (no run yet).")
            return
        self.fleet.config.speed = float(self.speed_var.get())
        self.state_store.save(self.fleet.config, self.fleet.summary(),
                              len(self.fleet.events()))
        self.status_var.set("state.md + state/last-session.json updated.")

    def on_load_state(self) -> None:
        data = self.state_store.load()
        if not data:
            messagebox.showinfo("Load state", "No saved state found.")
            return
        cfg = AppConfig.from_dict(data.get("config", {}))
        # rebuild profile forms from loaded config
        for f in list(self.profile_forms):
            f.destroy()
        self.profile_forms.clear()
        prof_box = self.profile_forms_parent
        for p in cfg.profiles:
            f = ProfileForm(prof_box, p)
            f.grid(row=len(self.profile_forms) * 2, column=0, columnspan=2,
                   sticky="we", padx=2, pady=3)
            self.profile_forms.append(f)
        self.seed_var.set(str(cfg.seed))
        self.duration_var.set(str(cfg.duration_s))
        self.speed_var.set(str(cfg.speed))
        messagebox.showinfo("Load state",
                            "Loaded. Server fields not restored; adjust if needed.")

    def on_export(self) -> None:
        if not self.fleet:
            messagebox.showinfo("Export", "Start a run first.")
            return
        path = self.memory_store.export_run(self.fleet.config,
                                            self.fleet.summary(),
                                            self.fleet.events())
        self.status_var.set(f"Exported: {path}")

    def on_export_csv(self) -> None:
        """Export profile metrics CSV + per-agent stats CSV as a matched pair."""
        if not self.fleet:
            messagebox.showinfo("Export CSV", "Start a run first.")
            return
        from persistence.csvexport import export_all
        try:
            paths = export_all(self.fleet.summary(), self.fleet.metrics)
        except OSError as e:
            messagebox.showerror("Export CSV", f"Write failed: {e}")
            return
        self.status_var.set("Exported: " + " · ".join(os.path.basename(p) for p in paths))

    def on_export_csv_as(self) -> None:
        """Ask for a base file name, then write <base>_metrics.csv + <base>_agents.csv."""
        if not self.fleet:
            messagebox.showinfo("Export CSV As", "Start a run first.")
            return
        initial = "checkin_" + time.strftime("%Y%m%d-%H%M%S")
        chosen = filedialog.asksaveasfilename(
            title="Export CSV — choose a base name (suffixes _metrics/_agents are added)",
            defaultextension=".csv",
            initialfile=initial,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not chosen:
            return  # user cancelled
        from persistence.csvexport import export_all_to_base
        try:
            paths = export_all_to_base(self.fleet.summary(), self.fleet.metrics,
                                       chosen)
        except OSError as e:
            messagebox.showerror("Export CSV As", f"Write failed: {e}")
            return
        self.status_var.set("Exported: " + " · ".join(os.path.basename(p) for p in paths))

    def on_toggle_log_pause(self) -> None:
        self.log_paused = not self.log_paused
        self.log_pause_btn.configure(text="▶ Resume log" if self.log_paused
                                     else "⏸ Pause log")

    # ------------------------------------------------------------- polling
    def _poll_queue(self) -> None:
        drained: List[Dict] = []
        try:
            while True:
                drained.append(self.event_queue.get_nowait())
        except queue.Empty:
            pass
        if drained and not self.log_paused:
            self._append_log(drained)
        if drained:
            self._chart_dirty = True
        self._update_clock()

        # rerender charts at most once per second
        if self._chart_dirty and self.chart_canvas is not None:
            now = time.monotonic()
            if now - self._last_chart_render >= 1.0:
                self._render_charts()
                self._last_chart_render = now
                self._chart_dirty = False

        # auto-refresh metrics every second while running
        if self.fleet and self.fleet.is_running():
            self._render_metrics(self.fleet.summary())

        self.after(POLL_MS, self._poll_queue)

    # ----------------------------------------------------------------- log
    def _append_log(self, events: List[Dict]) -> None:
        self.log_text.configure(state="normal")
        try:
            for ev in events:
                if self.log_line_count >= RING_LIMIT:
                    # drop oldest half to keep memory bounded
                    self.log_text.delete("1.0", f"{RING_LIMIT // 2}.0")
                    self.log_line_count = RING_LIMIT // 2
                self.log_line_count += 1
                tag, line = self._format_event(ev)
                self.log_text.insert("end", line + "\n", tag)
        finally:
            self.log_text.configure(state="disabled")
            self.log_text.see("end")

    @staticmethod
    def _format_event(ev: Dict):
        t = ev.get("sim_t", 0.0)
        if ev["type"] in ("checkin", "retry"):
            mark = "RETRY" if ev["type"] == "retry" else "CHK "
            tag = "ok" if ev["ok"] else "fail"
            line = (f"[{t:10.2f}s] {mark} agent={ev['agent_id']:<4d} "
                    f"profile={ev['profile']:<12s} try={ev['attempt']:<3d} "
                    f"drift={ev['drift'] * 1000:7.1f}ms "
                    f"lat={ev['latency_ms']:4d}ms status={ev['status']}")
            return tag, line
        if ev["type"] == "lockout":
            return "warn", (f"[{t:10.2f}s] LOCK  agent={ev['agent_id']:<4d} "
                            f"opened for {ev.get('duration_s', 0):.1f}s")
        if ev["type"] == "start":
            return "info", (f"[{t:10.2f}s] START fingerprint={ev.get('config_fingerprint')}")
        if ev["type"] == "end":
            return "info", (f"[{t:10.2f}s] END   agent={ev.get('agent_id', '?')} "
                            f"reason={ev.get('reason')}")
        return "info", f"[{t:10.2f}s] {ev}"

    # ------------------------------------------------------------- metrics
    def _render_metrics(self, summary: Dict) -> None:
        tree = self.metrics_tree
        tree.delete(*tree.get_children())
        for name, s in summary.get("profiles", {}).items():
            tree.insert("", "end", values=(
                name, s.get("agents"), s.get("checkins"), s.get("successes"),
                (s.get("failures") or 0) + (s.get("retries") or 0),
                s.get("retries"),
                self._fmt_num(s.get("interval_mean_s")),
                self._fmt_num(s.get("interval_std_s")),
                self._fmt_num(s.get("drift_p50_s")),
                self._fmt_num(s.get("drift_p95_s")),
                self._fmt_num(s.get("drift_max_s"))))

    @staticmethod
    def _fmt_num(v) -> str:
        return f"{v:.3f}" if isinstance(v, float) else ("—" if v is None else str(v))

    # -------------------------------------------------------------- charts
    def _render_charts(self) -> None:
        if self.fleet is None or self.chart_canvas is None:
            return
        summary = self.fleet.summary()
        events = self.fleet.events()

        # 1) arrival histogram per bucket
        self.ax_arr.clear()
        buckets = self.fleet.server.load_buckets()
        if buckets:
            xs = [b * self.fleet.server.bucket_seconds() for b, _ in buckets]
            ys = [n for _, n in buckets]
            self.ax_arr.bar(xs, ys, width=self.fleet.server.bucket_seconds() * 0.9,
                            color="#4477aa")
        self.ax_arr.set_title("Check-ins per load bucket (herd = spikes)")
        self.ax_arr.set_ylabel("arrivals")

        # 2) drift scatter
        self.ax_drift.clear()
        xs = [e["sim_t"] for e in events if e["type"] in ("checkin", "retry")]
        ys = [e["drift"] * 1000.0 for e in events if e["type"] in ("checkin", "retry")]
        self.ax_drift.scatter(xs, ys, s=4, alpha=0.4, color="#b3261e")
        self.ax_drift.set_title("Drift per check-in (actual − scheduled)")
        self.ax_drift.set_ylabel("drift (ms)")

        # 3) interval distribution per profile (first profile only if multiple)
        self.ax_int.clear()
        profiles = self.fleet.metrics.by_profile()
        if profiles:
            name = next(iter(profiles))
            samples = []
            for m in self.fleet.metrics.all():
                if m.profile_name == name:
                    samples.extend(m.interval_samples())
            if samples:
                self.ax_int.hist(samples, bins=40, color="#228833", alpha=0.85)
        self.ax_int.set_title(f"Realized intervals — {name if profiles else 'n/a'}")
        self.ax_int.set_xlabel("seconds")
        self.ax_int.set_ylabel("count")

        self.fig.tight_layout(pad=2.5)
        self.chart_canvas.draw_idle()

    # ---------------------------------------------------------------- clock
    def _update_clock(self) -> None:
        if self.fleet:
            self.clock_var.set(f"sim t={self.fleet.elapsed_s():.1f}s")
        else:
            self.clock_var.set("sim t=0.0s")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
