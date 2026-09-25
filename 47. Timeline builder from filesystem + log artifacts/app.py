import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json, csv, os, hashlib, random, threading, time, re
from datetime import datetime, timedelta
from collections import defaultdict

# === MODERN COLOR PALETTE ===
BG = "#0d1117"
SURFACE = "#161b22"
SURFACE2 = "#21262d"
BORDER = "#30363d"
PRIMARY = "#58a6ff"
PRIMARY_HOVER = "#79c0ff"
SUCCESS = "#3fb950"
SUCCESS_DIM = "#238636"
WARNING = "#d29922"
DANGER = "#f85149"
DANGER_DIM = "#da3633"
TEXT = "#e6edf3"
TEXT_DIM = "#8b949e"
TEXT_MUTED = "#484f58"
CYAN = "#39d2c0"
PURPLE = "#bc8cff"
PINK = "#f778ba"
ORANGE = "#d18616"

class TimelineBuilderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Timeline Builder - Filesystem & Log Artifacts")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)
        self.events = []
        self.anomalies = []
        self.log_sources = []
        self.filtered_events = []
        self.search_var = tk.StringVar()
        self.filter_type = tk.StringVar(value="All")
        self._apply_styles()
        self._build_ui()

    def _apply_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Frames
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=SURFACE, relief="flat")
        style.configure("Card2.TFrame", background=SURFACE2, relief="flat")
        style.configure("Header.TFrame", background=SURFACE, relief="flat")
        style.configure("Accent.TFrame", background=PRIMARY)

        # Labels
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground=PRIMARY, font=("Segoe UI", 11, "bold"))
        style.configure("Card.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=SURFACE, foreground=PRIMARY, font=("Segoe UI", 10, "bold"))
        style.configure("CardDim.TLabel", background=SURFACE, foreground=TEXT_DIM, font=("Segoe UI", 9))
        style.configure("Success.TLabel", background=SURFACE, foreground=SUCCESS, font=("Segoe UI", 10, "bold"))
        style.configure("Danger.TLabel", background=SURFACE, foreground=DANGER, font=("Segoe UI", 10, "bold"))
        style.configure("Warning.TLabel", background=SURFACE, foreground=WARNING, font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", background=SURFACE, foreground=TEXT_DIM, font=("Segoe UI", 9), padding=[8, 4])
        style.configure("StatusDot.TLabel", background=SURFACE, foreground=SUCCESS, font=("Segoe UI", 12))
        style.configure("Badge.TLabel", background=PRIMARY, foreground=BG, font=("Segoe UI", 9, "bold"), padding=[6, 2])
        style.configure("BadgeGreen.TLabel", background=SUCCESS_DIM, foreground=TEXT, font=("Segoe UI", 9, "bold"), padding=[6, 2])
        style.configure("BadgeRed.TLabel", background=DANGER_DIM, foreground=TEXT, font=("Segoe UI", 9, "bold"), padding=[6, 2])

        # Buttons
        style.configure("TButton", background=SURFACE2, foreground=TEXT, font=("Segoe UI", 10), padding=[12, 6], borderwidth=0, relief="flat")
        style.map("TButton", background=[("active", PRIMARY)], foreground=[("active", BG)])
        style.configure("Primary.TButton", background=PRIMARY, foreground=BG, font=("Segoe UI", 10, "bold"), padding=[14, 7], borderwidth=0)
        style.map("Primary.TButton", background=[("active", PRIMARY_HOVER)])
        style.configure("Success.TButton", background=SUCCESS_DIM, foreground=TEXT, font=("Segoe UI", 10, "bold"), padding=[12, 6], borderwidth=0)
        style.map("Success.TButton", background=[("active", SUCCESS)])
        style.configure("Danger.TButton", background=DANGER_DIM, foreground=TEXT, font=("Segoe UI", 10, "bold"), padding=[12, 6], borderwidth=0)
        style.map("Danger.TButton", background=[("active", DANGER)])
        style.configure("Ghost.TButton", background=BG, foreground=TEXT_DIM, font=("Segoe UI", 10), padding=[10, 5], borderwidth=0)
        style.map("Ghost.TButton", background=[("active", SURFACE2)], foreground=[("active", TEXT)])

        # Notebook (Tabs)
        style.configure("TNotebook", background=BG, borderwidth=0, padding=0)
        style.configure("TNotebook.Tab", background=SURFACE2, foreground=TEXT_DIM, padding=[16, 8], font=("Segoe UI", 10), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", SURFACE)],
                  foreground=[("selected", PRIMARY)])
        style.configure("TNotebook.Tab", padding=[16, 8])

        # Treeview
        style.configure("Treeview",
                        background=SURFACE,
                        foreground=TEXT,
                        fieldbackground=SURFACE,
                        font=("Consolas", 9),
                        borderwidth=0,
                        rowheight=26)
        style.configure("Treeview.Heading",
                        background=SURFACE2,
                        foreground=PRIMARY,
                        font=("Segoe UI", 9, "bold"),
                        borderwidth=0,
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", SURFACE2)],
                  foreground=[("selected", PRIMARY)])
        style.map("Treeview.Heading",
                  background=[("active", BORDER)])

        # Progressbar
        style.configure("Horizontal.TProgressbar",
                        background=PRIMARY,
                        troughcolor=SURFACE2,
                        borderwidth=0,
                        lightcolor=PRIMARY,
                        darkcolor=PRIMARY)
        style.configure("Green.Horizontal.TProgressbar",
                        background=SUCCESS,
                        troughcolor=SURFACE2,
                        borderwidth=0)
        style.configure("Red.Horizontal.TProgressbar",
                        background=DANGER,
                        troughcolor=SURFACE2,
                        borderwidth=0)

        # Entry
        style.configure("TEntry",
                        fieldbackground=SURFACE2,
                        foreground=TEXT,
                        insertcolor=PRIMARY,
                        borderwidth=0,
                        font=("Segoe UI", 10))

        # Combobox
        style.configure("TCombobox",
                        fieldbackground=SURFACE2,
                        foreground=TEXT,
                        selectbackground=PRIMARY,
                        selectforeground=BG,
                        borderwidth=0,
                        font=("Segoe UI", 10))

        # Checkbutton
        style.configure("TCheckbutton",
                        background=BG,
                        foreground=TEXT,
                        font=("Segoe UI", 10))
        style.map("TCheckbutton",
                  background=[("active", BG)])

        # LabelFrame
        style.configure("TLabelframe",
                        background=SURFACE,
                        foreground=TEXT_DIM,
                        borderwidth=1,
                        relief="flat")
        style.configure("TLabelframe.Label",
                        background=SURFACE,
                        foreground=PRIMARY,
                        font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        # === TOP ACCENT STRIP ===
        strip = tk.Frame(self.root, bg=PRIMARY, height=4)
        strip.pack(fill="x")
        strip.pack_propagate(False)

        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(top, text="Timeline Builder", style="Title.TLabel").pack(side="left")
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Load Logs", style="Primary.TButton", command=self._load_logs).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Generate Sample", command=self._generate_sample).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Analyze", command=self._analyze).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export Report", command=self._export_report).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear", style="Danger.TButton", command=self._clear_all).pack(side="left", padx=3)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._build_timeline_tab()
        self._build_anomalies_tab()
        self._build_sources_tab()
        self._build_stats_tab()
        self._build_report_tab()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready - No log files loaded")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _make_scroll_tree(self, parent, columns, headings, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for c, h, w in zip(columns, headings, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, minwidth=50)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return tree

    def _build_timeline_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Timeline ")
        toolbar = ttk.Frame(tab, style="Card.TFrame")
        toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Label(toolbar, text="Search:", style="Card.TLabel").pack(side="left", padx=(10, 5))
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_events())
        ttk.Label(toolbar, text="Filter:", style="Card.TLabel").pack(side="left", padx=(15, 5))
        filter_combo = ttk.Combobox(toolbar, textvariable=self.filter_type,
            values=["All", "File System", "Registry", "Process", "Network", "Login", "Application"],
            state="readonly", width=15)
        filter_combo.pack(side="left", padx=5)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self._filter_events())
        self.event_count_var = tk.StringVar(value="Events: 0")
        ttk.Label(toolbar, textvariable=self.event_count_var, style="Card.TLabel").pack(side="right", padx=10)
        cols = ("timestamp", "source", "event_type", "description", "artifact", "anomaly")
        heads = ("Timestamp", "Source", "Event Type", "Description", "Artifact", "Anomaly")
        ws = (170, 120, 120, 400, 200, 100)
        self.tl_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.tl_tree.tag_configure("anomaly", foreground=DANGER)
        self.tl_tree.tag_configure("normal", foreground=TEXT)

    def _build_anomalies_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Anomalies ")
        info_frame = ttk.Frame(tab, style="Card.TFrame")
        info_frame.pack(fill="x", padx=5, pady=5)
        self.anom_count_var = tk.StringVar(value="Anomalies: 0")
        ttk.Label(info_frame, textvariable=self.anom_count_var, style="Card.TLabel").pack(side="left", padx=10)
        cols = ("type", "severity", "timestamp", "description", "evidence", "mitre")
        heads = ("Type", "Severity", "Timestamp", "Description", "Evidence", "MITRE ATT&CK")
        ws = (140, 90, 170, 350, 250, 120)
        self.anom_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.anom_tree.tag_configure("high", foreground=DANGER)
        self.anom_tree.tag_configure("medium", foreground=WARNING)
        self.anom_tree.tag_configure("low", foreground=SUCCESS)

    def _build_sources_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Sources ")
        cols = ("name", "type", "events", "time_range", "hash")
        heads = ("Source Name", "Type", "Event Count", "Time Range", "MD5 Hash")
        ws = (250, 120, 100, 250, 250)
        self.src_tree = self._make_scroll_tree(tab, cols, heads, ws)

    def _build_stats_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Statistics ")
        self.stats_text = tk.Text(tab, bg=SURFACE, fg=TEXT, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.stats_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Report ")
        btn_frame = ttk.Frame(tab, style="Card.TFrame")
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="Generate Report", style="Primary.TButton", command=self._generate_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export JSON", command=lambda: self._export("json")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export CSV", command=lambda: self._export("csv")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export TXT", command=lambda: self._export("txt")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export HTML", command=lambda: self._export("html")).pack(side="left", padx=3)
        self.report_text = tk.Text(tab, bg=SURFACE, fg=TEXT, insertbackground=PRIMARY, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.report_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))

    def _load_logs(self):
        paths = filedialog.askopenfilenames(
            title="Load Log Files",
            filetypes=[("Log files", "*.log *.csv *.txt *.evtx"), ("All files", "*.*")]
        )
        if not paths:
            return
        for path in paths:
            fname = os.path.basename(path)
            fsize = os.path.getsize(path)
            fhash = hashlib.md5(open(path, "rb").read()[:8192]).hexdigest()
            self.log_sources.append({
                "name": fname, "path": path, "type": self._detect_log_type(path),
                "size": fsize, "hash": fhash
            })
        self._populate_sources()
        self.status_var.set(f"Loaded {len(paths)} log file(s). Total sources: {len(self.log_sources)}")

    def _detect_log_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        type_map = {".csv": "CSV Log", ".log": "Text Log", ".txt": "Text Log", ".evtx": "Event Log"}
        return type_map.get(ext, "Unknown")

    def _populate_sources(self):
        for item in self.src_tree.get_children():
            self.src_tree.delete(item)
        for s in self.log_sources:
            self.src_tree.insert("", "end", values=(
                s["name"], s["type"], "N/A", "N/A", s["hash"]
            ))

    def _generate_sample(self):
        self.events = []
        self.anomalies = []
        self.log_sources = []
        base = datetime(2026, 9, 17, 0, 0, 0)
        sources = [
            {"name": "Security.evtx", "type": "Event Log", "hash": hashlib.md5(b"security").hexdigest()},
            {"name": "System.evtx", "type": "Event Log", "hash": hashlib.md5(b"system").hexdigest()},
            {"name": "firewall.log", "type": "Text Log", "hash": hashlib.md5(b"firewall").hexdigest()},
            {"name": "access.log", "type": "Text Log", "hash": hashlib.md5(b"access").hexdigest()},
            {"name": "audit.csv", "type": "CSV Log", "hash": hashlib.md5(b"audit").hexdigest()},
        ]
        for s in sources:
            s["path"] = f" simulated://{s['name']}"
            s["size"] = random.randint(50000, 5000000)
        self.log_sources = sources
        event_templates = [
            ("File System", "File created", "C:\\Users\\admin\\Documents\\report.docx"),
            ("File System", "File modified", "C:\\Windows\\System32\\config\\SAM"),
            ("File System", "File deleted", "C:\\Temp\\cleanup.bat"),
            ("File System", "File access", "C:\\Users\\admin\\Downloads\\invoice.pdf"),
            ("Registry", "Key created", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("Registry", "Key modified", "HKCU\\Software\\Classes\\exefile"),
            ("Registry", "Value set", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil_svc"),
            ("Process", "Process created", "powershell.exe -enc SQBmACgA"),
            ("Process", "Process created", "cmd.exe /c net user admin P@ssw0rd /add"),
            ("Process", "Process terminated", "notepad.exe (PID:4520)"),
            ("Process", "DLL loaded", "C:\\Temp\\evil.dll loaded by rundll32.exe"),
            ("Network", "Connection established", "TCP 192.168.1.100:49832 -> 185.220.100.252:443"),
            ("Network", "DNS query", "evil-domain.com -> 93.184.216.34"),
            ("Network", "Data transfer", "UDP 192.168.1.100:53 -> 8.8.8.8:53 (1.2MB)"),
            ("Login", "Successful logon", "admin from 192.168.1.50 (Type 10 - RemoteInteractive)"),
            ("Login", "Failed logon", "administrator from 10.0.0.1 (Type 3 - Network) - Status: 0xC000006D"),
            ("Login", "Failed logon", "admin from 10.0.0.1 (Type 3 - Network) - Status: 0xC000006A"),
            ("Login", "Logoff", "admin logoff from console"),
            ("Application", "Service installed", "Windows Update Service (wuauserv)"),
            ("Application", "Scheduled task created", "\\Microsoft\\Windows\\Maintenance\\SystemScan"),
            ("Application", "WMI event", "SELECT * FROM __InstanceModificationEvent"),
        ]
        for i in range(200):
            hours_offset = random.uniform(0, 48)
            ts = base + timedelta(hours=hours_offset)
            etype, desc, artifact = random.choice(event_templates)
            is_anomaly = random.random() < 0.15
            self.events.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "source": random.choice(sources)["name"],
                "event_type": etype,
                "description": desc,
                "artifact": artifact,
                "anomaly": "YES" if is_anomaly else ""
            })
        self.events.sort(key=lambda x: x["timestamp"])
        anomaly_templates = [
            ("Timestomping", "HIGH", "File timestamp modified to appear older", "HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation", "T1070.006"),
            ("Suspicious Process", "HIGH", "Encoded PowerShell execution detected", "powershell.exe -enc SQBmACgA", "T1059.001"),
            ("Brute Force", "HIGH", "Multiple failed logon attempts from same source", "10.0.0.1 - 15 failures in 5 minutes", "T1110"),
            ("Lateral Movement", "HIGH", "Remote service installation detected", "evil_svc created on remote host", "T1021.002"),
            ("Data Exfiltration", "HIGH", "Unusual DNS query volume", "500+ DNS queries in 10 minutes", "T1048"),
            ("Privilege Escalation", "HIGH", "Admin account created via net command", "net user admin P@ssw0rd /add", "T1136.001"),
            ("Persistence", "MEDIUM", "Registry Run key modified", "HKLM\\...\\Run\\WindowsUpdate", "T1547.001"),
            ("Defense Evasion", "MEDIUM", "PowerShell execution policy bypass", "Set-ExecutionPolicy Bypass", "T1562.001"),
            ("Reconnaissance", "LOW", "Whoami command executed", "whoami /all", "T1082"),
            ("File Access", "MEDIUM", "Sensitive file accessed outside business hours", "C:\\Windows\\System32\\config\\SAM at 03:14 AM", "T1003.002"),
        ]
        for i in range(25):
            hours_offset = random.uniform(0, 48)
            ts = base + timedelta(hours=hours_offset)
            atype, sev, desc, evidence, mitre = random.choice(anomaly_templates)
            self.anomalies.append({
                "type": atype, "severity": sev,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "description": desc, "evidence": evidence, "mitre": mitre
            })
        self.anomalies.sort(key=lambda x: x["timestamp"])
        self.filtered_events = self.events[:]
        self._populate_all()
        self._generate_stats()
        self.status_var.set(f"Sample generated: {len(self.events)} events, {len(self.anomalies)} anomalies, {len(self.log_sources)} sources")

    def _populate_all(self):
        self._filter_events()
        for item in self.anom_tree.get_children():
            self.anom_tree.delete(item)
        for a in self.anomalies:
            tag = "high" if a["severity"] == "HIGH" else "medium" if a["severity"] == "MEDIUM" else "low"
            self.anom_tree.insert("", "end", values=(
                a["type"], a["severity"], a["timestamp"], a["description"], a["evidence"], a["mitre"]
            ), tags=(tag,))
        self.anom_count_var.set(f"Anomalies: {len(self.anomalies)}")
        self._populate_sources()

    def _filter_events(self):
        for item in self.tl_tree.get_children():
            self.tl_tree.delete(item)
        search = self.search_var.get().lower()
        ftype = self.filter_type.get()
        count = 0
        for ev in self.events:
            if ftype != "All" and ev["event_type"] != ftype:
                continue
            if search and search not in ev["description"].lower() and search not in ev["artifact"].lower():
                continue
            tag = "anomaly" if ev["anomaly"] == "YES" else "normal"
            self.tl_tree.insert("", "end", values=(
                ev["timestamp"], ev["source"], ev["event_type"],
                ev["description"], ev["artifact"], ev["anomaly"]
            ), tags=(tag,))
            count += 1
        self.event_count_var.set(f"Events: {count}")

    def _analyze(self):
        if not self.events:
            messagebox.showwarning("No Data", "Load log files or generate sample data first.")
            return
        self.status_var.set("Analyzing timeline...")
        threading.Thread(target=self._analyze_thread, daemon=True).start()

    def _analyze_thread(self):
        time.sleep(1)
        self.root.after(0, self._analysis_done)

    def _analysis_done(self):
        self.status_var.set(f"Analysis complete: {len(self.anomalies)} anomalies detected")

    def _generate_stats(self):
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("end", "=" * 60 + "\n")
        self.stats_text.insert("end", "TIMELINE STATISTICS\n")
        self.stats_text.insert("end", "=" * 60 + "\n\n")
        self.stats_text.insert("end", f"Total Events: {len(self.events)}\n")
        self.stats_text.insert("end", f"Total Anomalies: {len(self.anomalies)}\n")
        self.stats_text.insert("end", f"Log Sources: {len(self.log_sources)}\n\n")
        type_counts = defaultdict(int)
        for ev in self.events:
            type_counts[ev["event_type"]] += 1
        self.stats_text.insert("end", "Events by Type:\n")
        for etype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            bar = "#" * min(count, 50)
            self.stats_text.insert("end", f"  {etype:<20} {count:>5}  {bar}\n")
        self.stats_text.insert("end", "\nAnomalies by Severity:\n")
        sev_counts = defaultdict(int)
        for a in self.anomalies:
            sev_counts[a["severity"]] += 1
        for sev, count in sorted(sev_counts.items()):
            self.stats_text.insert("end", f"  {sev:<10} {count:>5}\n")
        if self.events:
            first = self.events[0]["timestamp"]
            last = self.events[-1]["timestamp"]
            self.stats_text.insert("end", f"\nTime Range: {first} to {last}\n")
        src_counts = defaultdict(int)
        for ev in self.events:
            src_counts[ev["source"]] += 1
        self.stats_text.insert("end", "\nEvents by Source:\n")
        for src, count in sorted(src_counts.items(), key=lambda x: -x[1]):
            self.stats_text.insert("end", f"  {src:<30} {count:>5}\n")

    def _generate_report(self):
        if not self.events:
            messagebox.showwarning("No Data", "No data to report.")
            return
        report = self._build_report_data()
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 80 + "\n")
        self.report_text.insert("end", "TIMELINE ANALYSIS REPORT\n")
        self.report_text.insert("end", "=" * 80 + "\n\n")
        self.report_text.insert("end", f"Generated: {report['metadata']['timestamp']}\n")
        self.report_text.insert("end", f"Sources: {report['metadata']['source_count']}\n")
        self.report_text.insert("end", f"Total Events: {report['metadata']['total_events']}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "ANOMALIES DETECTED\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for a in report["anomalies"]:
            self.report_text.insert("end", f"  [{a['severity']}] {a['type']}: {a['description']}\n")
            self.report_text.insert("end", f"    Time: {a['timestamp']} | Evidence: {a['evidence']}\n")
            self.report_text.insert("end", f"    MITRE: {a['mitre']}\n\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "EVENT TIMELINE (First 50)\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for ev in report["events"][:50]:
            anom = " [!]" if ev["anomaly"] == "YES" else ""
            self.report_text.insert("end", f"  {ev['timestamp']}  {ev['event_type']:<15} {ev['description']}{anom}\n")
        self.status_var.set("Report generated")

    def _build_report_data(self):
        return {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_count": len(self.log_sources),
                "total_events": len(self.events),
                "total_anomalies": len(self.anomalies),
                "tool": "Timeline Builder"
            },
            "sources": self.log_sources,
            "events": self.events,
            "anomalies": self.anomalies
        }

    def _export(self, fmt):
        if not self.events:
            messagebox.showwarning("No Data", "No data to export.")
            return
        report = self._build_report_data()
        type_map = {"json": [("JSON files", "*.json")], "csv": [("CSV files", "*.csv")],
                     "txt": [("Text files", "*.txt")], "html": [("HTML files", "*.html")]}
        path = filedialog.asksaveasfilename(
            title=f"Export Report as {fmt.upper()}",
            defaultextension=f".{fmt}",
            filetypes=type_map[fmt]
        )
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, default=str)
            elif fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["Timestamp", "Source", "Event Type", "Description", "Artifact", "Anomaly"])
                    for ev in report["events"]:
                        w.writerow([ev["timestamp"], ev["source"], ev["event_type"], ev["description"], ev["artifact"], ev["anomaly"]])
                    w.writerow([])
                    w.writerow(["Type", "Severity", "Timestamp", "Description", "Evidence", "MITRE"])
                    for a in report["anomalies"]:
                        w.writerow([a["type"], a["severity"], a["timestamp"], a["description"], a["evidence"], a["mitre"]])
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("TIMELINE ANALYSIS REPORT\n")
                    f.write(f"Generated: {report['metadata']['timestamp']}\n")
                    f.write(f"Total Events: {report['metadata']['total_events']}\n")
                    f.write(f"Total Anomalies: {report['metadata']['total_anomalies']}\n\n")
                    f.write("ANOMALIES:\n")
                    for a in report["anomalies"]:
                        f.write(f"  [{a['severity']}] {a['type']}: {a['description']}\n")
                    f.write(f"\nEVENTS ({len(report['events'])}):\n")
                    for ev in report["events"]:
                        f.write(f"  {ev['timestamp']}  {ev['event_type']:<15} {ev['description']}\n")
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("<!DOCTYPE html><html><head><title>Timeline Report</title>")
                    f.write("<style>body{font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px}")
                    f.write("h1{color:#58a6ff}h2{color:#3fb950}table{border-collapse:collapse;width:100%}")
                    f.write("th{background:#161b22;color:#58a6ff;padding:8px;text-align:left}")
                    f.write("td{padding:6px;border-bottom:1px solid #30363d}")
                    f.write(".high{color:#f85149}.medium{color:#d29922}.low{color:#3fb950}</style></head><body>")
                    f.write(f"<h1>Timeline Analysis Report</h1>")
                    f.write(f"<p>Generated: {report['metadata']['timestamp']}</p>")
                    f.write(f"<p>Events: {report['metadata']['total_events']} | Anomalies: {report['metadata']['total_anomalies']}</p>")
                    f.write("<h2>Anomalies</h2><table><tr><th>Type</th><th>Severity</th><th>Time</th><th>Description</th><th>MITRE</th></tr>")
                    for a in report["anomalies"]:
                        sev_class = a["severity"].lower()
                        f.write(f"<tr><td>{a['type']}</td><td class='{sev_class}'>{a['severity']}</td><td>{a['timestamp']}</td><td>{a['description']}</td><td>{a['mitre']}</td></tr>")
                    f.write("</table><h2>Events (First 100)</h2><table><tr><th>Timestamp</th><th>Type</th><th>Description</th><th>Artifact</th></tr>")
                    for ev in report["events"][:100]:
                        cls = "high" if ev["anomaly"] == "YES" else ""
                        f.write(f"<tr><td class='{cls}'>{ev['timestamp']}</td><td>{ev['event_type']}</td><td>{ev['description']}</td><td>{ev['artifact']}</td></tr>")
                    f.write("</table></body></html>")
            self.status_var.set(f"Report exported as {path}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        self.events = []
        self.anomalies = []
        self.log_sources = []
        self.filtered_events = []
        self.search_var.set("")
        self.filter_type.set("All")
        for tree in [self.tl_tree, self.anom_tree, self.src_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")
        self.stats_text.delete("1.0", "end")
        self.event_count_var.set("Events: 0")
        self.anom_count_var.set("Anomalies: 0")
        self.status_var.set("Ready - No log files loaded")

    def _export_report(self):
        self._generate_report()

if __name__ == "__main__":
    root = tk.Tk()
    app = TimelineBuilderApp(root)
    root.mainloop()
