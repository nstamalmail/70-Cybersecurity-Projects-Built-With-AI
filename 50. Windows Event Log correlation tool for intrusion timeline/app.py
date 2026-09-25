import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json, csv, os, hashlib, random, threading, time
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

EVENT_TEMPLATES = [
    {"id": 4624, "level": "Information", "task": "Logon", "desc": "An account was successfully logged on", "mitre": "T1078"},
    {"id": 4625, "level": "Information", "task": "Logoff", "desc": "An account was logged off", "mitre": "T1078"},
    {"id": 4634, "level": "Information", "task": "Logoff", "desc": "An account was logged off", "mitre": "T1078"},
    {"id": 4623, "level": "Information", "task": "Special Logon", "desc": "A special logon was assigned", "mitre": "T1078"},
    {"id": 4672, "level": "Information", "task": "Special Privileges", "desc": "Special privileges assigned to new logon", "mitre": "T1078.003"},
    {"id": 4720, "level": "Information", "task": "Account Created", "desc": "A user account was created", "mitre": "T1136.001"},
    {"id": 4726, "level": "Information", "task": "Account Deleted", "desc": "A user account was deleted", "mitre": "T1531"},
    {"id": 4728, "level": "Information", "task": "Member Added", "desc": "A member was added to a security-enabled local group", "mitre": "T1078.003"},
    {"id": 4732, "level": "Information", "task": "Member Added", "desc": "A member was added to a local group", "mitre": "T1078.003"},
    {"id": 4735, "level": "Information", "task": "Group Changed", "desc": "A local group was changed", "mitre": "T1078.003"},
    {"id": 4756, "level": "Information", "task": "Member Added", "desc": "A member was added to a security-enabled universal group", "mitre": "T1078.003"},
    {"id": 4648, "level": "Warning", "task": "Logon Using Explicit", "desc": "A logon was attempted using explicit credentials", "mitre": "T1550.002"},
    {"id": 4649, "level": "Warning", "task": "Kerberos Replay", "desc": "A replay attack was detected", "mitre": "T1550.003"},
    {"id": 4771, "level": "Warning", "task": "Kerberos Pre-Auth Failed", "desc": "Kerberos pre-authentication failed", "mitre": "T1110"},
    {"id": 4776, "level": "Information", "task": "NTLM Auth", "desc": "The computer attempted to validate the credentials for an account", "mitre": "T1110.001"},
    {"id": 4778, "level": "Information", "task": "Session Reconnect", "desc": "A terminal services session was reconnected", "mitre": "T1021.001"},
    {"id": 4779, "level": "Information", "task": "Session Disconnect", "desc": "A terminal services session was disconnected", "mitre": "T1021.001"},
    {"id": 5140, "level": "Information", "task": "Network Share", "desc": "A network object was accessed", "mitre": "T1135"},
    {"id": 5145, "level": "Information", "task": "Network Share Check", "desc": "A network share object was checked", "mitre": "T1135"},
    {"id": 4698, "level": "Information", "task": "Scheduled Task Created", "desc": "A scheduled task was successfully created", "mitre": "T1053.005"},
    {"id": 4699, "level": "Information", "task": "Scheduled Task Deleted", "desc": "A scheduled task was successfully deleted", "mitre": "T1053.005"},
    {"id": 4702, "level": "Information", "task": "Scheduled Task Updated", "desc": "A scheduled task was updated", "mitre": "T1053.005"},
    {"id": 4688, "level": "Information", "task": "Process Created", "desc": "A new process has been created", "mitre": "T1059"},
    {"id": 4689, "level": "Information", "task": "Process Terminated", "desc": "A process has exited", "mitre": "T1059"},
    {"id": 4104, "level": "Warning", "task": "PowerShell Script", "desc": "PowerShell Script block logging", "mitre": "T1059.001"},
    {"id": 4103, "level": "Information", "task": "PowerShell Module", "desc": "PowerShell Module logging", "mitre": "T1059.001"},
    {"id": 7045, "level": "Information", "task": "Service Installed", "desc": "A new service was installed in the system", "mitre": "T1543.003"},
    {"id": 7040, "level": "Information", "task": "Service Changed", "desc": "The start type of a service was changed", "mitre": "T1543.003"},
    {"id": 1102, "level": "Critical", "task": "Audit Log Cleared", "desc": "The audit log was cleared", "mitre": "T1070.001"},
    {"id": 4719, "level": "Warning", "task": "Audit Policy Changed", "desc": "System audit policy was changed", "mitre": "T1562.001"},
    {"id": 4738, "level": "Information", "task": "User Account Changed", "desc": "A user account was changed", "mitre": "T1098"},
    {"id": 4742, "level": "Information", "task": "Computer Account Changed", "desc": "A computer account was changed", "mitre": "T1098"},
    {"id": 4765, "level": "Information", "task": "SID History Added", "desc": "SID History was added to an account", "mitre": "T1134.005"},
    {"id": 4766, "level": "Warning", "task": "SID History Attempt", "desc": "An attempt to add SID History failed", "mitre": "T1134.005"},
    {"id": 1102, "level": "Critical", "task": "Log Cleared", "desc": "Security log was cleared", "mitre": "T1070.001"},
    {"id": 4697, "level": "Information", "task": "Service Installed", "desc": "A service was installed in the system", "mitre": "T1543.003"},
    {"id": 4657, "level": "Information", "task": "Registry Modified", "desc": "A registry value was modified", "mitre": "T1574.001"},
    {"id": 4663, "level": "Information", "task": "Object Access", "desc": "An attempt was made to access an object", "mitre": "T1005"},
]

SUSPICIOUS_SEQUENCES = [
    {
        "name": "Brute Force Attack",
        "description": "Multiple failed logon attempts followed by success",
        "events": [4771, 4771, 4771, 4625, 4624],
        "severity": "HIGH",
        "mitre": "T1110",
        "indicators": "Event IDs 4771 repeated, then 4624"
    },
    {
        "name": "Privilege Escalation",
        "description": "Special privileges assigned followed by account creation",
        "events": [4672, 4720, 4728],
        "severity": "HIGH",
        "mitre": "T1078.003",
        "indicators": "4672 -> 4720 -> 4728 sequence"
    },
    {
        "name": "Lateral Movement via SMB",
        "description": "Network share access followed by process creation",
        "events": [5140, 4688],
        "severity": "HIGH",
        "mitre": "T1021.002",
        "indicators": "5140 -> 4688 on remote host"
    },
    {
        "name": "Persistence - Scheduled Task",
        "description": "Scheduled task creation for persistence",
        "events": [4698, 7045],
        "severity": "MEDIUM",
        "mitre": "T1053.005",
        "indicators": "4698 followed by 7045"
    },
    {
        "name": "Defense Evasion - Log Clearing",
        "description": "Audit log cleared to hide tracks",
        "events": [1102],
        "severity": "CRITICAL",
        "mitre": "T1070.001",
        "indicators": "Event ID 1102 (Log Cleared)"
    },
    {
        "name": "Credential Access - Kerberoasting",
        "description": "Kerberos pre-auth failures indicating offline cracking",
        "events": [4771, 4771, 4771, 4771, 4771],
        "severity": "HIGH",
        "mitre": "T1558.003",
        "indicators": "Multiple 4771 events in short time window"
    },
    {
        "name": "Execution - PowerShell",
        "description": "PowerShell script block execution detected",
        "events": [4104, 4688],
        "severity": "MEDIUM",
        "mitre": "T1059.001",
        "indicators": "4104 with encoded command content"
    },
]

class WindowsEventLogApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Log Correlation Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)
        self.events = []
        self.correlations = []
        self.suspicious = []
        self.loaded_files = []
        self.search_var = tk.StringVar()
        self.level_filter = tk.StringVar(value="All")
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
        ttk.Label(top, text="Windows Event Log Correlation", style="Title.TLabel").pack(side="left")
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Load Logs", style="Primary.TButton", command=self._load_logs).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Simulate", style="TButton", command=self._generate_sample).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Correlate", style="TButton", command=self._correlate).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export Report", style="TButton", command=self._export_report).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear", style="Danger.TButton", command=self._clear_all).pack(side="left", padx=3)

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready - No event logs loaded")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._build_events_tab()
        self._build_correlations_tab()
        self._build_mitre_tab()
        self._build_report_tab()

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

    def _build_events_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Events ")
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Label(toolbar, text="Search:", style="Card.TLabel").pack(side="left", padx=(10, 5))
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_events())
        ttk.Label(toolbar, text="Level:", style="Card.TLabel").pack(side="left", padx=(15, 5))
        level_combo = ttk.Combobox(toolbar, textvariable=self.level_filter,
            values=["All", "Critical", "Error", "Warning", "Information"],
            state="readonly", width=12)
        level_combo.pack(side="left", padx=5)
        level_combo.bind("<<ComboboxSelected>>", lambda e: self._filter_events())
        self.event_count_var = tk.StringVar(value="Events: 0")
        ttk.Label(toolbar, textvariable=self.event_count_var, style="Card.TLabel").pack(side="right", padx=10)
        cols = ("time_created", "event_id", "level", "task", "provider", "computer", "description")
        heads = ("Time Created", "Event ID", "Level", "Task", "Provider", "Computer", "Description")
        ws = (170, 80, 90, 150, 180, 120, 350)
        self.event_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.event_tree.tag_configure("critical", foreground=DANGER)
        self.event_tree.tag_configure("warning", foreground=WARNING)
        self.event_tree.tag_configure("error", foreground=ORANGE)
        self.event_tree.tag_configure("info", foreground=TEXT_DIM)

    def _build_correlations_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Correlations ")
        self.corr_count_var = tk.StringVar(value="Correlations: 0")
        info_frame = ttk.Frame(tab)
        info_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(info_frame, textvariable=self.corr_count_var, style="Card.TLabel").pack(side="left", padx=10)
        cols = ("name", "severity", "description", "events", "indicators", "mitre")
        heads = ("Pattern Name", "Severity", "Description", "Event Sequence", "Indicators", "MITRE")
        ws = (200, 90, 300, 150, 300, 100)
        self.corr_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.corr_tree.tag_configure("critical", foreground=DANGER)
        self.corr_tree.tag_configure("high", foreground=ORANGE)
        self.corr_tree.tag_configure("medium", foreground=WARNING)

    def _build_mitre_tab(self):
        tab = ttk.Frame(self.root)
        self.notebook.add(tab, text=" MITRE ATT&CK ")
        self.mitre_text = tk.Text(tab, bg=SURFACE, fg=TEXT, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.mitre_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Report ")
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="Generate Report", style="Primary.TButton", command=self._generate_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export JSON", style="TButton", command=lambda: self._export("json")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export CSV", style="TButton", command=lambda: self._export("csv")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export TXT", style="TButton", command=lambda: self._export("txt")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export HTML", style="TButton", command=lambda: self._export("html")).pack(side="left", padx=3)
        self.report_text = tk.Text(tab, bg=SURFACE, fg=TEXT, insertbackground=TEXT, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.report_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))

    def _load_logs(self):
        paths = filedialog.askopenfilenames(
            title="Load Event Log Files",
            filetypes=[("Event logs", "*.evtx *.xml"), ("All files", "*.*")]
        )
        if not paths:
            return
        for p in paths:
            self.loaded_files.append(os.path.basename(p))
        self.status_var.set(f"Loaded {len(paths)} log file(s). Generating simulated events...")
        self._generate_sample()

    def _generate_sample(self):
        self.events = []
        self.correlations = []
        self.suspicious = []
        random.seed(int(time.time()))
        base = datetime(2026, 9, 17, 0, 0, 0)
        providers = ["Microsoft-Windows-Security-Auditing", "Microsoft-Windows-System",
                     "Microsoft-Windows-PowerShell", "Service Control Manager",
                     "Microsoft-Windows-TaskScheduler", "Microsoft-Windows-Registry"]
        computers = ["DC01", "WORKSTATION01", "FILESERVER01", "WEB01"]
        users = ["admin", "jsmith", "svc_backup", "Administrator", "guest", "SYSTEM"]
        for i in range(500):
            template = random.choice(EVENT_TEMPLATES)
            hours_offset = random.uniform(0, 72)
            ts = base + timedelta(hours=hours_offset)
            level = template["level"]
            user = random.choice(users)
            desc = template["desc"]
            if template["id"] == 4624:
                logon_type = random.choice([2, 3, 10, 11])
                desc = f"An account was successfully logged on. Logon Type: {logon_type}. Account: {user}"
            elif template["id"] == 4688:
                proc = random.choice(["cmd.exe", "powershell.exe", "net.exe", "whoami.exe", "systeminfo.exe", "notepad.exe"])
                desc = f"A new process has been created. Process: {proc}. Account: {user}"
            elif template["id"] == 4104:
                desc = f"PowerShell Script block logging. Script: Get-Process | Export-Csv. Account: {user}"
            elif template["id"] == 7045:
                svc = random.choice(["WindowsUpdate", "RemoteAccess", "evil_svc", "BackdoorService"])
                desc = f"A new service was installed. Service: {svc}. Account: {user}"
            elif template["id"] == 4720:
                desc = f"A user account was created. New Account: newuser_{random.randint(1,99)}"
            elif template["id"] == 1102:
                desc = "The audit log was cleared. Subject: Administrator"
            self.events.append({
                "time_created": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": template["id"],
                "level": level,
                "task": template["task"],
                "provider": random.choice(providers),
                "computer": random.choice(computers),
                "description": desc,
                "user": user,
                "mitre": template["mitre"],
                "sort_time": ts
            })
        self.events.sort(key=lambda x: x["sort_time"])
        for ev in self.events:
            del ev["sort_time"]
        self._populate_events()
        self._run_correlation()
        self._generate_mitre_map()
        self.status_var.set(f"Generated {len(self.events)} events. Correlation complete.")

    def _populate_events(self):
        self._filter_events()

    def _filter_events(self):
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)
        search = self.search_var.get().lower()
        level = self.level_filter.get()
        count = 0
        for ev in self.events:
            if level != "All" and ev["level"] != level:
                continue
            if search and search not in ev["description"].lower() and search not in ev["task"].lower():
                continue
            tag_map = {"Critical": "critical", "Error": "error", "Warning": "warning", "Information": "info"}
            tag = tag_map.get(ev["level"], "info")
            self.event_tree.insert("", "end", values=(
                ev["time_created"], ev["event_id"], ev["level"], ev["task"],
                ev["provider"], ev["computer"], ev["description"]
            ), tags=(tag,))
            count += 1
        self.event_count_var.set(f"Events: {count}")

    def _correlate(self):
        if not self.events:
            messagebox.showwarning("No Data", "No events to correlate.")
            return
        self.status_var.set("Running correlation engine...")
        threading.Thread(target=self._correlate_thread, daemon=True).start()

    def _correlate_thread(self):
        time.sleep(1)
        self.root.after(0, self._run_correlation)

    def _run_correlation(self):
        self.correlations = []
        self.suspicious = []
        event_ids = [ev["event_id"] for ev in self.events]
        for seq in SUSPICIOUS_SEQUENCES:
            pattern = seq["events"]
            found = False
            for i in range(len(event_ids) - len(pattern) + 1):
                if event_ids[i:i+len(pattern)] == pattern:
                    found = True
                    break
            if found:
                self.correlations.append({
                    "name": seq["name"],
                    "severity": seq["severity"],
                    "description": seq["description"],
                    "events": " -> ".join(str(e) for e in pattern),
                    "indicators": seq["indicators"],
                    "mitre": seq["mitre"]
                })
                self.suspicious.append(seq["name"])
        id_counts = defaultdict(int)
        for ev in self.events:
            id_counts[ev["event_id"]] += 1
        if id_counts.get(1102, 0) > 0:
            if "Defense Evasion - Log Clearing" not in self.suspicious:
                self.correlations.append({
                    "name": "Defense Evasion - Log Clearing",
                    "severity": "CRITICAL",
                    "description": "Audit log cleared to hide tracks",
                    "events": "1102",
                    "indicators": f"{id_counts[1102]} log clear event(s) detected",
                    "mitre": "T1070.001"
                })
                self.suspicious.append("Defense Evasion - Log Clearing")
        if id_counts.get(4771, 0) > 5:
            self.correlations.append({
                "name": "Kerberoasting Suspected",
                "severity": "HIGH",
                "description": f"Excessive Kerberos pre-auth failures: {id_counts[4771]} events",
                "events": "4771 (x" + str(id_counts[4771]) + ")",
                "indicators": "More than 5 Kerberos pre-auth failures",
                "mitre": "T1558.003"
            })
        self._populate_correlations()
        self.corr_count_var.set(f"Correlations: {len(self.correlations)}")
        self.status_var.set(f"Correlation complete: {len(self.correlations)} suspicious patterns found")

    def _populate_correlations(self):
        for item in self.corr_tree.get_children():
            self.corr_tree.delete(item)
        for c in self.correlations:
            sev_tag = c["severity"].lower()
            if sev_tag not in ("critical", "high", "medium"):
                sev_tag = "medium"
            self.corr_tree.insert("", "end", values=(
                c["name"], c["severity"], c["description"],
                c["events"], c["indicators"], c["mitre"]
            ), tags=(sev_tag,))

    def _generate_mitre_map(self):
        self.mitre_text.delete("1.0", "end")
        self.mitre_text.insert("end", "=" * 60 + "\n")
        self.mitre_text.insert("end", "MITRE ATT&CK MAPPING\n")
        self.mitre_text.insert("end", "=" * 60 + "\n\n")
        tactic_map = {
            "T1078": ("Initial Access", "Valid Accounts"),
            "T1078.003": ("Persistence", "Local Accounts"),
            "T1110": ("Credential Access", "Brute Force"),
            "T1059": ("Execution", "Command and Scripting Interpreter"),
            "T1059.001": ("Execution", "PowerShell"),
            "T1053.005": ("Execution", "Scheduled Task"),
            "T1136.001": ("Persistence", "Local Account"),
            "T1021.002": ("Lateral Movement", "SMB/Windows Admin Shares"),
            "T1021.001": ("Lateral Movement", "Remote Desktop Protocol"),
            "T1550.002": ("Defense Evasion", "Pass the Hash"),
            "T1550.003": ("Defense Evasion", "Pass the Ticket"),
            "T1070.001": ("Defense Evasion", "Clear Windows Event Logs"),
            "T1562.001": ("Defense Evasion", "Disable or Modify Tools"),
            "T1543.003": ("Persistence", "Windows Service"),
            "T1134.005": ("Defense Evasion", "SID History"),
            "T1558.003": ("Credential Access", "Kerberoasting"),
            "T1005": ("Collection", "Data from Local System"),
            "T1135": ("Discovery", "Network Share Discovery"),
            "T1574.001": ("Defense Evasion", "DLL Search Order Hijacking"),
            "T1098": ("Persistence", "Account Manipulation"),
            "T1531": ("Impact", "Account Access Removal"),
            "T1082": ("Discovery", "System Information Discovery"),
        }
        mitre_events = defaultdict(list)
        for ev in self.events:
            if ev["mitre"] in tactic_map:
                mitre_events[ev["mitre"]].append(ev)
        for tactic_id in sorted(mitre_events.keys()):
            if tactic_id in tactic_map:
                tactic, technique = tactic_map[tactic_id]
                count = len(mitre_events[tactic_id])
                self.mitre_text.insert("end", f"[{tactic}] {technique} ({tactic_id})\n")
                self.mitre_text.insert("end", f"  Events: {count}\n")
                for ev in mitre_events[tactic_id][:3]:
                    self.mitre_text.insert("end", f"    {ev['time_created']}  {ev['event_id']}  {ev['description'][:80]}\n")
                if count > 3:
                    self.mitre_text.insert("end", f"    ... and {count - 3} more\n")
                self.mitre_text.insert("end", "\n")

    def _generate_report(self):
        if not self.events:
            messagebox.showwarning("No Data", "No data to report.")
            return
        report = self._build_report_data()
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 80 + "\n")
        self.report_text.insert("end", "WINDOWS EVENT LOG CORRELATION REPORT\n")
        self.report_text.insert("end", "=" * 80 + "\n\n")
        self.report_text.insert("end", f"Generated: {report['metadata']['timestamp']}\n")
        self.report_text.insert("end", f"Total Events: {report['metadata']['total_events']}\n")
        self.report_text.insert("end", f"Correlations: {report['metadata']['correlation_count']}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "SUSPICIOUS ACTIVITIES\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for c in report["correlations"]:
            self.report_text.insert("end", f"  [{c['severity']}] {c['name']}\n")
            self.report_text.insert("end", f"    {c['description']}\n")
            self.report_text.insert("end", f"    Events: {c['events']} | MITRE: {c['mitre']}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "EVENT SUMMARY\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        level_counts = defaultdict(int)
        for ev in report["events"]:
            level_counts[ev["level"]] += 1
        for level, count in sorted(level_counts.items()):
            self.report_text.insert("end", f"  {level:<15} {count:>5}\n")
        self.status_var.set("Report generated")

    def _build_report_data(self):
        return {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_events": len(self.events),
                "correlation_count": len(self.correlations),
                "sources": self.loaded_files,
                "tool": "Windows Event Log Correlation Tool"
            },
            "events": self.events,
            "correlations": self.correlations,
            "suspicious": self.suspicious
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
                    w.writerow(["Time Created", "Event ID", "Level", "Task", "Description", "Computer"])
                    for ev in report["events"]:
                        w.writerow([ev["time_created"], ev["event_id"], ev["level"], ev["task"], ev["description"], ev["computer"]])
                    w.writerow([])
                    w.writerow(["Name", "Severity", "Description", "Events", "MITRE"])
                    for c in report["correlations"]:
                        w.writerow([c["name"], c["severity"], c["description"], c["events"], c["mitre"]])
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("WINDOWS EVENT LOG CORRELATION REPORT\n")
                    f.write(f"Generated: {report['metadata']['timestamp']}\n")
                    f.write(f"Total Events: {report['metadata']['total_events']}\n\n")
                    f.write("SUSPICIOUS ACTIVITIES:\n")
                    for c in report["correlations"]:
                        f.write(f"  [{c['severity']}] {c['name']}: {c['description']}\n")
                    f.write(f"\nEVENTS ({len(report['events'])}):\n")
                    for ev in report["events"][:100]:
                        f.write(f"  {ev['time_created']}  {ev['event_id']:<6} {ev['level']:<12} {ev['description'][:80]}\n")
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("<!DOCTYPE html><html><head><title>Event Log Report</title>")
                    f.write(f"<style>body{{font-family:monospace;background:{BG};color:{TEXT};padding:20px}}")
                    f.write(f"h1{{color:{PRIMARY}}}h2{{color:{SUCCESS}}}table{{border-collapse:collapse;width:100%}}")
                    f.write(f"th{{background:{SURFACE2};color:{PRIMARY};padding:8px;text-align:left}}")
                    f.write(f"td{{padding:6px;border-bottom:1px solid {BORDER}}}")
                    f.write(f".critical{{color:{DANGER}}}.high{{color:{ORANGE}}}.medium{{color:{WARNING}}}.info{{color:{TEXT_DIM}}}</style></head><body>")
                    f.write(f"<h1>Windows Event Log Report</h1>")
                    f.write(f"<p>Generated: {report['metadata']['timestamp']}</p>")
                    f.write(f"<p>Events: {report['metadata']['total_events']} | Correlations: {report['metadata']['correlation_count']}</p>")
                    f.write("<h2>Suspicious Activities</h2><table><tr><th>Severity</th><th>Pattern</th><th>Description</th><th>MITRE</th></tr>")
                    for c in report["correlations"]:
                        sev_class = c["severity"].lower()
                        f.write(f"<tr><td class='{sev_class}'>{c['severity']}</td><td>{c['name']}</td><td>{c['description']}</td><td>{c['mitre']}</td></tr>")
                    f.write("</table><h2>Events (First 100)</h2><table><tr><th>Time</th><th>ID</th><th>Level</th><th>Description</th></tr>")
                    for ev in report["events"][:100]:
                        lvl_class = ev["level"].lower()
                        f.write(f"<tr><td class='{lvl_class}'>{ev['time_created']}</td><td>{ev['event_id']}</td><td class='{lvl_class}'>{ev['level']}</td><td>{ev['description'][:80]}</td></tr>")
                    f.write("</table></body></html>")
            self.status_var.set(f"Report exported as {path}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        self.events = []
        self.correlations = []
        self.suspicious = []
        self.loaded_files = []
        self.search_var.set("")
        self.level_filter.set("All")
        for tree in [self.event_tree, self.corr_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")
        self.mitre_text.delete("1.0", "end")
        self.event_count_var.set("Events: 0")
        self.corr_count_var.set("Correlations: 0")
        self.status_var.set("Ready - No event logs loaded")

    def _export_report(self):
        self._generate_report()

if __name__ == "__main__":
    root = tk.Tk()
    app = WindowsEventLogApp(root)
    root.mainloop()
