"""Main window: layout, toolbar, menus, queue-poll event loop, export actions."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, List, Optional

from .. import __version__
from ..capture import (
    CaptureController,
    PcapFileEngine,
    PcapReader,
    PcapWriter,
    SnifferConfig,
    list_interfaces,
)
from ..capture.stats import StatisticsAggregator
from ..display_filter import compile_filter, validate_filter
from ..models import Packet
from ..utils.platform import IS_WINDOWS, elevate_windows, is_admin
from .dialogs import show_about, show_error, show_notice
from .panels import DetailTreePanel, HexPanel, PacketListPanel
from .stats_panel import StatisticsPanel

POLL_MS = 80                      # GUI poll interval
BATCH_MAX = 200                   # max rows inserted per poll tick


class MainWindow:
    def __init__(self, root: tk.Tk, skip_notice: bool = False):
        self.root = root
        self.root.title(f"PacketSniffer {__version__} — raw socket capture")
        self.root.geometry("1180x760")

        self.packet_queue: "queue.Queue[Packet]" = queue.Queue()
        self.displayed: List[Packet] = []
        self.filter_fn = compile_filter("")
        self.stats = StatisticsAggregator()
        self.controller = CaptureController()
        self.controller.set_on_packet(self._on_capture_packet)
        self.controller.set_on_state(self._on_state_change)
        self._filter_error: Optional[str] = None
        self._session_start: Optional[float] = None
        self._closing = False

        self._build_menu()
        self._build_toolbar()
        self._build_panes()
        self._build_statusbar()

        if not skip_notice:
            if not show_notice(self.root):
                self.root.after(50, self.root.destroy)
                return
        self.refresh_interfaces()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(POLL_MS, self._poll)

    # ------------------------------------------------------------------ UI --
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Open capture (.pcap)…", command=self.open_pcap)
        m_file.add_separator()
        m_file.add_command(label="Save displayed packets as .pcap…", command=self.save_pcap)
        m_file.add_command(label="Export displayed packets as JSON…", command=self.export_json)
        m_file.add_command(label="Export displayed packets as CSV…", command=self.export_csv)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=m_file)

        m_cap = tk.Menu(menubar, tearoff=0)
        m_cap.add_command(label="Start capture", command=self.start_capture)
        m_cap.add_command(label="Stop", command=self.stop_capture)
        m_cap.add_command(label="Clear", command=self.clear_packets)
        m_cap.add_separator()
        self.resolve_var = tk.BooleanVar(value=False)
        self.record_var = tk.BooleanVar(value=False)
        m_cap.add_checkbutton(label="Resolve hostnames (reverse DNS)",
                              variable=self.resolve_var, onvalue=True, offvalue=False)
        m_cap.add_checkbutton(label="Record to pcap while capturing",
                              variable=self.record_var, onvalue=True, offvalue=False)
        menubar.add_cascade(label="Capture", menu=m_cap)

        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="Ethical use notice", command=lambda: show_notice(self.root))
        m_help.add_command(label="About", command=lambda: show_about(self.root, __version__))
        menubar.add_cascade(label="Help", menu=m_help)
        self.root.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 4))
        bar.pack(side=tk.TOP, fill=tk.X)

        self.btn_start = ttk.Button(bar, text="▶ Start", command=self.start_capture, width=9)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop = ttk.Button(bar, text="■ Stop", command=self.stop_capture, width=9,
                                   state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=(4, 10))

        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(bar, textvariable=self.iface_var, width=32,
                                        state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=(4, 10))

        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=42)
        self.filter_entry.pack(side=tk.LEFT, padx=(4, 4), fill=tk.X, expand=True)
        self.filter_entry.bind("<Return>", self._apply_filter)
        self.filter_entry.bind("<KeyRelease>", self._validate_typing)
        self.filter_status = ttk.Label(bar, text="", width=28)
        self.filter_status.pack(side=tk.LEFT)

        self.btn_clear = ttk.Button(bar, text="Clear", command=self.clear_packets, width=8)
        self.btn_clear.pack(side=tk.LEFT, padx=(10, 4))
        self.btn_save = ttk.Button(bar, text="Save…", command=self.save_pcap, width=8)
        self.btn_save.pack(side=tk.LEFT)

    def _build_panes(self) -> None:
        main = ttk.Panedwindow(self.root, orient=tk.VERTICAL)

        # top: packet list
        top = ttk.Frame(main)
        self.packet_panel = PacketListPanel(top, on_select=self._on_row_selected)
        self.packet_panel.pack(fill=tk.BOTH, expand=True)

        # middle notebook: detail / hex / stats
        bottom = ttk.Frame(main)
        self.detail_panel = DetailTreePanel(bottom)
        self.hex_panel = HexPanel(bottom)
        self.stats_panel = StatisticsPanel(bottom)
        self.notebook = ttk.Notebook(bottom)
        self.notebook.add(self.detail_panel, text="Packet details")
        self.notebook.add(self.hex_panel, text="Hex dump")
        self.notebook.add(self.stats_panel, text="Statistics")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        main.add(top, weight=3)
        main.add(bottom, weight=2)
        main.pack(fill=tk.BOTH, expand=True)

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar(value="Ready — open a .pcap or start a capture")
        bar = ttk.Frame(self.root, padding=(6, 2))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(bar, textvariable=self.status_var, anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.counts_var = tk.StringVar(value="0 packets")
        ttk.Label(bar, textvariable=self.counts_var).pack(side=tk.RIGHT)

    # ------------------------------------------------------------ actions --
    def refresh_interfaces(self) -> None:
        try:
            ifaces = list_interfaces()
        except Exception:
            ifaces = []
        names = [i["name"] for i in ifaces] or ["default"]
        self._iface_map = {i["name"]: i for i in ifaces}
        self.iface_combo["values"] = names
        if names and names != ["default"]:
            self.iface_combo.current(0)

    def start_capture(self) -> None:
        if self.controller.state != "idle":
            return
        if IS_WINDOWS and not is_admin():
            if messagebox.askyesno(
                    "Administrator required",
                    "Raw socket capture on Windows requires Administrator privileges.\n"
                    "Restart PacketSniffer elevated now?", parent=self.root):
                elevate_windows()
                self.root.after(100, self._on_close_silent)
                return
            else:
                messagebox.showinfo(
                    "Continuing unelevated",
                    "Live capture will fail until elevated. You can still open .pcap files.",
                    parent=self.root)
                return
        if not is_admin() and not IS_WINDOWS:
            messagebox.showwarning(
                "Root required",
                "POSIX raw sockets require root or CAP_NET_RAW.\n"
                "Capture may fail; try: sudo python main.py", parent=self.root)

        iface_name = self.iface_var.get()
        info = getattr(self, "_iface_map", {}).get(iface_name, {})
        config = SnifferConfig(
            interface=(info.get("ip") or iface_name),
            promiscuous=True,
            name=iface_name,
        )
        self.stats.start_session()
        self._session_start = time.time()
        if self.record_var.get():
            path = filedialog.asksaveasfilename(
                defaultextension=".pcap", filetypes=[("pcap capture", "*.pcap")],
                title="Record capture to", parent=self.root)
            if path:
                self.controller.start_recording(path)
        try:
            self.controller.start(config)
        except PermissionError as exc:
            show_error(self.root, "Permission denied", str(exc))
            return
        except Exception as exc:
            show_error(self.root, "Capture failed", str(exc))
            return
        self._set_capture_ui(True)
        self.status_var.set(f"Capturing on {config.name} …")

    def stop_capture(self) -> None:
        self.controller.stop()
        self._set_capture_ui(False)
        self.status_var.set("Capture stopped")

    def clear_packets(self) -> None:
        self.packet_panel.clear()
        self.detail_panel.show_packet(None)
        self.hex_panel.show_packet(None)
        self.stats_panel.clear()
        self.displayed.clear()
        self.counts_var.set("0 packets")

    def open_pcap(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("pcap capture", "*.pcap"), ("All files", "*.*")],
            title="Open capture", parent=self.root)
        if not path:
            return
        self.open_pcap_path(path)

    def open_pcap_path(self, path: str) -> None:
        """Open a pcap by absolute path (menu action and CLI entrypoint)."""
        if self.controller.state != "idle":
            self.controller.stop()
            self._set_capture_ui(False)
        self.clear_packets()
        config = SnifferConfig(name=os.path.basename(path), link_layer=True)
        engine = PcapFileEngine(config, path)
        try:
            engine.open()                # fail fast on bad files
            engine.close()
        except Exception as exc:
            show_error(self.root, "Cannot open capture", str(exc))
            return
        self.stats.start_session()
        self._session_start = time.time()
        self.controller.start(config, engine=engine)
        self._set_capture_ui(True)
        self.status_var.set(f"Replaying {os.path.basename(path)} …")

    # -- export ------------------------------------------------------------------
    def save_pcap(self) -> None:
        if not self.displayed:
            messagebox.showinfo("Nothing to save", "No displayed packets to save.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("pcap capture", "*.pcap")],
            title="Save displayed packets", parent=self.root)
        if not path:
            return
        writer = PcapWriter(path)
        try:
            for pkt in self.displayed:
                writer.write_packet(pkt.timestamp, pkt.raw, pkt.orig_len)
        finally:
            writer.close()
        self.status_var.set(f"Saved {len(self.displayed)} packets → {path}")

    def export_json(self) -> None:
        self._export(".json", "JSON", self._packets_to_json)

    def export_csv(self) -> None:
        self._export(".csv", "CSV", self._packets_to_csv)

    def _export(self, ext: str, label: str, producer) -> None:
        if not self.displayed:
            messagebox.showinfo("Nothing to export", f"No displayed packets to export as {label}.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(defaultextension=ext, title=f"Export {label}",
                                            parent=self.root)
        if not path:
            return
        try:
            producer(path)
            self.status_var.set(f"Exported {len(self.displayed)} packets → {path}")
        except Exception as exc:
            show_error(self.root, f"{label} export failed", str(exc))

    @staticmethod
    def _packets_to_json(path: str, packets: List[Packet]) -> None:
        out = []
        for p in packets:
            out.append({
                "number": p.number,
                "timestamp": p.timestamp,
                "length": p.frame_len,
                "protocol": p.protocol,
                "src": p.src,
                "dst": p.dst,
                "layers": [
                    {"name": l.name, "fields": {k: (v if isinstance(v, (int, str, bool, float)) else str(v))
                                                for k, v in l.fields.items()}}
                    for l in p.layers
                ],
            })
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, default=str)

    @staticmethod
    def _packets_to_csv(path: str, packets: List[Packet]) -> None:
        import csv
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["no", "time", "src", "dst", "protocol", "length", "info"])
            for p in packets:
                w.writerow(p.summary_row())

    # ------------------------------------------------------------ pipeline --
    def _on_capture_packet(self, pkt: Packet) -> None:
        """Called on the drain thread — just stash into the UI queue."""
        self.packet_queue.put(pkt)

    def _poll(self) -> None:
        """GUI-side queue drain — batch inserts, then refresh counters."""
        batch: List[Packet] = []
        try:
            while True:
                pkt = self.packet_queue.get_nowait()
                self.displayed.append(pkt)
                if self.filter_fn(pkt):
                    batch.append(pkt)
                    self.stats.update(pkt, True, dropped=self.controller.dropped)
                else:
                    self.stats.update(pkt, False, dropped=self.controller.dropped)
                if len(batch) >= BATCH_MAX:
                    break
        except queue.Empty:
            pass
        if batch:
            self.packet_panel.append_batch(batch)
            self._update_counts()
        self.root.after(POLL_MS, self._poll)

    def _update_counts(self) -> None:
        shown = self.packet_panel.packet_count()
        total = len(self.displayed)
        self.counts_var.set(f"{shown:,} shown / {total:,} captured")

    def _apply_filter(self, _event=None) -> None:
        text = self.filter_var.get()
        err = validate_filter(text)
        if err:
            self.filter_status.config(text=f"✗ {err[:40]}", foreground="#c0392b")
            return
        self.filter_fn = compile_filter(text)
        self.filter_status.config(text="✓ filter applied", foreground="#27ae60")
        # re-filter the retained window from scratch
        self.packet_panel.clear()
        for pkt in self.displayed[-self.packet_panel.max_rows:]:
            if self.filter_fn(pkt):
                self.packet_panel.append(pkt)
        self._update_counts()

    def _validate_typing(self, _event=None) -> None:
        text = self.filter_var.get().strip()
        if not text:
            self.filter_status.config(text="", foreground="#333333")
            return
        err = validate_filter(text)
        if err:
            self.filter_status.config(text=f"✗ {err[:40]}", foreground="#c0392b")
        else:
            self.filter_status.config(text="✓ valid", foreground="#27ae60")

    def _on_row_selected(self, pkt: Packet) -> None:
        self.detail_panel.show_packet(pkt)
        self.hex_panel.show_packet(pkt)

    def _on_state_change(self, state: str) -> None:
        def ui():
            if state == "capturing":
                self._set_capture_ui(True)
            elif state in ("idle", "error"):
                self._set_capture_ui(False)
                if state == "error":
                    err = self.controller.last_error() or "capture error"
                    self.status_var.set(f"Capture error: {err}")
        self.root.after(0, ui)

    def _set_capture_ui(self, capturing: bool) -> None:
        self.btn_start.config(state=tk.DISABLED if capturing else tk.NORMAL)
        self.btn_stop.config(state=tk.NORMAL if capturing else tk.DISABLED)
        self.iface_combo.config(state="disabled" if capturing else "readonly")

    # ------------------------------------------------------------ shutdown --
    def _on_close_silent(self) -> None:
        self._closing = True
        try:
            self.controller.stop()
        finally:
            self.root.destroy()

    def _on_close(self) -> None:
        self._closing = True
        self.controller.stop()
        self.root.destroy()
