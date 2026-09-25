"""ArpScannerApp — Tkinter GUI for the ARP scanner.

Threading contract (architecture.md §5.2): the Tk mainloop thread never
touches the network. The scanner runs in a daemon thread and publishes
ScanEvents to a queue.Queue; the UI drains it via root.after().
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import engine, exporter, interface
from core.models import Host, ScanConfig, ScanEvent, ScanResult

APP_TITLE = "ARP Scanner — Live-Host Discovery"
AUTH_NOTICE = (
    "ARP Scanner v1.0 — Live-Host Discovery\n\n"
    "Use only on networks you are authorized to assess.\n"
    "Scanning networks you do not own or administer may be illegal.\n\n"
    "Engine: Windows SendARP (no Npcap, no admin rights needed).\n"
    "Architecture doc: architecture.md"
)


class ArpScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("880x520")
        self.root.minsize(720, 420)

        self._event_queue: queue.Queue[ScanEvent] = queue.Queue()
        self._scan_thread: threading.Thread | None = None
        self._cancel_token = None
        self._last_result: ScanResult | None = None
        self._interfaces: list[dict] = []
        self._selected_iface: dict | None = None

        self._build_menu()
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()

        self._refresh_interfaces()
        self.root.after(100, self._drain_queue)

    # ------------------------------------------------------------ layout

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export CSV…", command=self._on_export_csv)
        file_menu.add_command(label="Export JSON…", command=self._on_export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(APP_TITLE, AUTH_NOTICE, parent=self.root))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=6)
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Adapter:").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(
            bar, textvariable=self.iface_var, state="readonly", width=44
        )
        self.iface_combo.pack(side=tk.LEFT, padx=(4, 8))
        self.iface_combo.bind("<<ComboboxSelected>>", self._on_iface_selected)

        ttk.Button(bar, text="↻", width=3, command=self._refresh_interfaces).pack(
            side=tk.LEFT
        )

        ttk.Label(bar, text="CIDR:").pack(side=tk.LEFT, padx=(10, 4))
        self.cidr_var = tk.StringVar()
        self.cidr_entry = ttk.Entry(bar, textvariable=self.cidr_var, width=18)
        self.cidr_entry.pack(side=tk.LEFT)

        self.scan_btn = ttk.Button(bar, text="▶ Scan", command=self._on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(10, 4))
        self.stop_btn = ttk.Button(bar, text="■ Stop", command=self._on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        self.csv_btn = ttk.Button(bar, text="Save CSV", command=self._on_export_csv, state=tk.DISABLED)
        self.csv_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self.json_btn = ttk.Button(bar, text="Save JSON", command=self._on_export_json, state=tk.DISABLED)
        self.json_btn.pack(side=tk.RIGHT)

    def _build_table(self) -> None:
        wrap = ttk.Frame(self.root, padding=(6, 0, 6, 0))
        wrap.pack(fill=tk.BOTH, expand=True)

        cols = ("ip", "mac", "vendor", "hostname")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        headers = {"ip": "IP Address", "mac": "MAC Address", "vendor": "Vendor", "hostname": "Hostname"}
        widths = {"ip": 130, "mac": 165, "vendor": 260, "hostname": 240}
        for c in cols:
            self.tree.heading(c, text=headers[c], command=lambda _c=c: self._sort_by(_c))
            self.tree.column(c, width=widths[c], anchor=tk.W, stretch=(c == "vendor"))

        vsb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.tree.tag_configure("odd", background="#f4f4f4")

        # double-click a row → try to open http://<ip> in browser? Keep it read-only;
        # copy MAC to clipboard instead (harmless, useful for inventories).
        self.tree.bind("<Double-1>", self._on_row_copy)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 4))
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="Ready. Select adapter and click Scan.")
        ttk.Label(bar, textvariable=self.status_var, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress = ttk.Progressbar(bar, mode="determinate", length=180)
        self.progress.pack(side=tk.RIGHT)

    # ------------------------------------------------------------ state

    def _refresh_interfaces(self) -> None:
        try:
            self._interfaces = interface.list_interfaces()
        except Exception as exc:  # non-Windows or API failure
            messagebox.showerror(APP_TITLE, f"Cannot enumerate adapters:\n{exc}", parent=self.root)
            self._interfaces = []

        self.iface_combo["values"] = [
            f"{a['description']} — {a['ip']}/{a['prefix']}" for a in self._interfaces
        ]
        if self._interfaces:
            default = interface.default_interface()
            idx = 0
            if default:
                for i, a in enumerate(self._interfaces):
                    if a["name"] == default["name"] and a["ip"] == default["ip"]:
                        idx = i
                        break
            self.iface_combo.current(idx)
            self._on_iface_selected()

    def _on_iface_selected(self, _evt=None) -> None:
        idx = self.iface_combo.current()
        self._selected_iface = self._interfaces[idx] if 0 <= idx < len(self._interfaces) else None
        if self._selected_iface:
            self.cidr_var.set(self._selected_iface["cidr"] or "")

    def _selected_cidr(self) -> str | None:
        cidr = self.cidr_var.get().strip()
        if not cidr:
            self._set_status("Enter a CIDR range (e.g. 192.168.1.0/24).", warn=True)
            return None
        try:
            import ipaddress
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version != 4:
                raise ValueError("IPv4 only")
        except ValueError as exc:
            self._set_status(f"Invalid CIDR: {exc}", warn=True)
            return None
        return str(net)

    # ------------------------------------------------------------ actions

    def _on_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return
        cidr = self._selected_cidr()
        if cidr is None:
            return

        config = ScanConfig(cidr=cidr)
        self._cancel_token = engine.make_cancel_token()
        self._clear_table()
        self._set_scan_running(True)
        self.progress["value"] = 0

        def job():
            try:
                engine.scan(
                    config,
                    event_cb=self._event_queue.put,
                    cancel_token=self._cancel_token,
                    interfaces=self._interfaces,
                )
            except Exception as exc:  # defensive: never kill the queue drain
                self._event_queue.put(ScanEvent("error", str(exc)))

        self._scan_thread = threading.Thread(target=job, name="scan-job", daemon=True)
        self._scan_thread.start()

    def _on_stop(self) -> None:
        if self._cancel_token:
            self._cancel_token.cancel()
            self._set_status("Stopping…")

    def _on_export_csv(self) -> None:
        self._export(".csv")

    def _on_export_json(self) -> None:
        self._export(".json")

    def _export(self, ext: str) -> None:
        if not self._last_result or not self._last_result.hosts:
            messagebox.showinfo(APP_TITLE, "No results to export yet.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=ext,
            filetypes=[(f"{ext[1:].upper()} file", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"arp_scan_{self._last_result.cidr.replace('/', '_').replace('.', '_')}{ext}",
        )
        if not path:
            return
        try:
            exporter.export(self._last_result, path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Export failed:\n{exc}", parent=self.root)
            return
        self._set_status(f"Exported {len(self._last_result.hosts)} hosts → {path}")

    def _on_row_copy(self, _evt) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(" ".join(str(v) for v in values))
        self._set_status("Row copied to clipboard.")

    # ------------------------------------------------------------ scan events

    def _drain_queue(self) -> None:
        """UI thread: pull all pending scan events, then reschedule."""
        try:
            while True:
                evt = self._event_queue.get_nowait()
                self._handle_event(evt)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _handle_event(self, evt: ScanEvent) -> None:
        if evt.kind == "start":
            info = evt.value
            self.progress["maximum"] = info["total"]
            self._set_status(f"Scanning {info['cidr']} — {info['total']} addresses…")
        elif evt.kind == "progress":
            info = evt.value
            self.progress["value"] = info["done"]
            found = len(self.tree.get_children())
            self._set_status(
                f"Scanning… {info['done']}/{info['total']} probed, {found} host(s) found"
            )
        elif evt.kind == "host":
            host: Host = evt.value
            rownum = len(self.tree.get_children())
            tags = ("odd",) if rownum % 2 else ()
            self.tree.insert("", tk.END, values=host.to_row(), tags=tags)
        elif evt.kind == "done":
            self._last_result = evt.value
            hosts = self._last_result.sorted_hosts()
            self._repopulate_table(hosts)
            self.progress["value"] = self.progress["maximum"]
            self._set_status(
                f"Done — {len(hosts)} host(s) found in {self._last_result.duration_s:.1f}s "
                f"on {self._last_result.cidr}"
            )
            self._set_scan_running(False)
        elif evt.kind == "error":
            messagebox.showerror(APP_TITLE, str(evt.value), parent=self.root)
            self._set_scan_running(False)

    def _repopulate_table(self, hosts: list[Host]) -> None:
        self._clear_table()
        for i, host in enumerate(hosts):
            tags = ("odd",) if i % 2 else ()
            self.tree.insert("", tk.END, values=host.to_row(), tags=tags)

    def _clear_table(self) -> self:
        for item in self.tree.get_children():
            self.tree.delete(item)
        return self

    def _set_scan_running(self, running: bool) -> None:
        state_scan = tk.DISABLED if running else tk.NORMAL
        state_stop = tk.NORMAL if running else tk.DISABLED
        self.scan_btn.config(state=state_scan)
        self.stop_btn.config(state=state_stop)
        self.csv_btn.config(state=state_scan)
        self.json_btn.config(state=state_scan)

    def _set_status(self, text: str, warn: bool = False) -> None:
        self.status_var.set(text)
        # Keep it simple: prefix warnings with ⚠
        if warn:
            self.status_var.set(f"⚠ {text}")

    def _sort_by(self, col: str) -> None:
        """Toggle sort on a column header click."""
        state_key = f"_sort_{col}_desc"
        desc = getattr(self, state_key, False)
        setattr(self, state_key, not desc)

        def key(ip_item):
            vals = self.tree.set(ip_item)
            v = vals.get(col, "")
            if col == "ip":
                try:
                    import ipaddress
                    return int(ipaddress.ip_address(v))
                except ValueError:
                    return 0
            return v.lower()

        items = sorted(self.tree.get_children(), key=key, reverse=desc)
        for i, item in enumerate(items):
            self.tree.move(item, "", i)

    # window close while scanning: daemon thread dies with the process
    def on_close(self) -> None:
        if self._cancel_token:
            self._cancel_token.cancel()
        self.root.destroy()


def run() -> None:
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass  # pre-Win8.1 or already set
    app = ArpScannerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
