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

BROWSERS = {
    "chrome": {
        "name": "Google Chrome",
        "history_db": "History",
        "cookies_db": "Cookies",
        "base_paths": [
            os.path.expanduser("~") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
            os.path.expanduser("~") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1",
        ]
    },
    "firefox": {
        "name": "Mozilla Firefox",
        "history_db": "places.sqlite",
        "cookies_db": "cookies.sqlite",
        "base_paths": [
            os.path.expanduser("~") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
        ]
    },
    "edge": {
        "name": "Microsoft Edge",
        "history_db": "History",
        "cookies_db": "Cookies",
        "base_paths": [
            os.path.expanduser("~") + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default",
        ]
    }
}

class BrowserArtifactExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Browser Artifact Extractor")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)
        self.history_entries = []
        self.cookie_entries = []
        self.download_entries = []
        self.loaded_browser = None
        self.search_var = tk.StringVar()
        self.browser_filter = tk.StringVar(value="All")
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
        ttk.Label(top, text="Browser Artifact Extractor", style="Title.TLabel").pack(side="left")
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Load Database", style="Primary.TButton", command=self._load_database).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Simulate Chrome", style="TButton", command=lambda: self._simulate("chrome")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Simulate Firefox", style="TButton", command=lambda: self._simulate("firefox")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Simulate Edge", style="TButton", command=lambda: self._simulate("edge")).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export Report", style="TButton", command=self._export_report).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear", style="Danger.TButton", command=self._clear_all).pack(side="left", padx=3)

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready - No browser database loaded")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._build_history_tab()
        self._build_cookies_tab()
        self._build_downloads_tab()
        self._build_stats_tab()
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

    def _build_history_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" History ")
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Label(toolbar, text="Search:", style="Card.TLabel").pack(side="left", padx=(10, 5))
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_history())
        self.history_count_var = tk.StringVar(value="Visits: 0")
        ttk.Label(toolbar, textvariable=self.history_count_var, style="Card.TLabel").pack(side="right", padx=10)
        cols = ("id", "url", "title", "visit_count", "last_visit", "typed_count", "browser")
        heads = ("ID", "URL", "Title", "Visits", "Last Visit", "Typed", "Browser")
        ws = (50, 350, 250, 70, 170, 70, 100)
        self.hist_tree = self._make_scroll_tree(tab, cols, heads, ws)

    def _build_cookies_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Cookies ")
        cols = ("host", "name", "value", "path", "expires", "secure", "http_only", "browser")
        heads = ("Host", "Name", "Value", "Path", "Expires", "Secure", "HttpOnly", "Browser")
        ws = (180, 180, 200, 120, 170, 70, 80, 100)
        self.cookie_tree = self._make_scroll_tree(tab, cols, heads, ws)

    def _build_downloads_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Downloads ")
        cols = ("id", "url", "filename", "start_time", "end_time", "size", "state", "danger")
        heads = ("ID", "URL", "Filename", "Started", "Completed", "Size", "State", "Danger")
        ws = (50, 350, 250, 170, 170, 100, 100, 100)
        self.dl_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.dl_tree.tag_configure("dangerous", foreground=DANGER)
        self.dl_tree.tag_configure("safe", foreground=SUCCESS)

    def _build_stats_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Statistics ")
        self.stats_text = tk.Text(tab, bg=SURFACE, fg=TEXT, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.stats_text.pack(fill="both", expand=True, padx=5, pady=5)

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

    def _load_database(self):
        path = filedialog.askopenfilename(
            title="Load Browser Database",
            filetypes=[("SQLite databases", "*.sqlite *.db *.sqlite3"), ("All files", "*.*")]
        )
        if not path:
            return
        self.loaded_browser = "custom"
        self.status_var.set(f"Loaded: {os.path.basename(path)} - Simulating data...")
        self._simulate("chrome")

    def _simulate(self, browser_type):
        self.history_entries = []
        self.cookie_entries = []
        self.download_entries = []
        random.seed(int(time.time()))
        base_time = datetime(2026, 9, 17, 0, 0, 0)
        browser_name = BROWSERS[browser_type]["name"]
        domains = [
            "google.com", "youtube.com", "github.com", "stackoverflow.com",
            "reddit.com", "twitter.com", "facebook.com", "linkedin.com",
            "wikipedia.org", "amazon.com", "netflix.com", "microsoft.com",
            "apple.com", "python.org", "docs.python.org", "pypi.org",
            "arxiv.org", "medium.com", "news.ycombinator.com", "gitlab.com",
            "jira.atlassian.com", "confluence.atlassian.com", "slack.com",
            "zoom.us", "office.com", "live.com", "outlook.com",
        ]
        paths_list = [
            "/search?q=forensics", "/trending", "/repo/analysis", "/wiki/Memory_forensics",
            "/login", "/dashboard", "/settings", "/profile", "/feed", "/notifications",
            "/downloads", "/docs/getting-started", "/tutorial/advanced", "/api/v2/reference",
            "/blog/security-update", "/article/2026-threats", "/video/lecture-1",
        ]
        titles = [
            "Google Search", "YouTube - Trending", "GitHub Dashboard", "Stack Overflow",
            "Reddit Front Page", "Twitter Home", "Facebook Feed", "LinkedIn Profile",
            "Wikipedia Article", "Amazon Shopping", "Netflix Browse", "Microsoft Docs",
            "Apple Support", "Python Documentation", "PyPI Package Index",
            "arXiv Papers", "Medium Stories", "Hacker News", "GitLab Projects",
        ]
        for i in range(150):
            domain = random.choice(domains)
            path = random.choice(paths_list)
            title = random.choice(titles)
            url = f"https://www.{domain}{path}"
            visit_count = random.randint(1, 50)
            hours_ago = random.uniform(0, 720)
            last_visit = base_time - timedelta(hours=hours_ago)
            typed_count = random.randint(0, 5)
            self.history_entries.append({
                "id": i + 1,
                "url": url,
                "title": f"{title} - {domain}",
                "visit_count": visit_count,
                "last_visit": last_visit.strftime("%Y-%m-%d %H:%M:%S"),
                "typed_count": typed_count,
                "browser": browser_name
            })
        cookie_names = [
            "_ga", "_gid", "__session", "auth_token", "csrf_token",
            "session_id", "user_pref", "consent", "tracking_opt_out",
            "lang", "theme", "last_search", "cart_items", "ab_test_group",
            "device_id", "fingerprint", "remember_me", "oauth_state",
        ]
        for i in range(80):
            domain = random.choice(domains)
            name = random.choice(cookie_names)
            value = hashlib.md5(f"{domain}{name}{i}".encode()).hexdigest()[:32]
            path = random.choice(["/", "/app", "/api", "/auth", "/static"])
            hours_until = random.uniform(24, 8760)
            expires = (base_time + timedelta(hours=hours_until)).strftime("%Y-%m-%d %H:%M:%S")
            secure = random.choice(["Yes", "No", "Yes", "Yes"])
            http_only = random.choice(["Yes", "No", "Yes"])
            self.cookie_entries.append({
                "host": f".{domain}",
                "name": name,
                "value": value,
                "path": path,
                "expires": expires,
                "secure": secure,
                "http_only": http_only,
                "browser": browser_name
            })
        dl_urls = [
            "https://github.com/downloads/release.zip",
            "https://dl.google.com/chrome/install/ChromeSetup.exe",
            "https://releases.mozilla.org/firefox/update.tar.gz",
            "https://aka.ms/vscode/VSCodeSetup.exe",
            "https://www.python.org/ftp/python/3.11.0/python-3.11.0.exe",
            "https://download.docker.com/win/stable/Docker%20Desktop%20Installer.exe",
            "https://git-scm.com/downloads/git-2.40.0.exe",
            "https://notepad-plus-plus.org/releases/v8.5/npp.8.5.Installer.exe",
            "https://archive.org/download/legacy-backup/backup.zip",
            "https://suspicious-domain.com/files/tool.exe",
        ]
        states = ["Completed", "Completed", "Completed", "In Progress", "Interrupted"]
        dangers = ["None", "None", "None", "None", "High", "Medium", "None"]
        for i in range(30):
            url = random.choice(dl_urls)
            filename = url.split("/")[-1].replace("%20", " ")
            hours_ago = random.uniform(0, 360)
            start_time = base_time - timedelta(hours=hours_ago)
            end_time = start_time + timedelta(seconds=random.randint(5, 300))
            size = random.randint(100000, 200000000)
            state = random.choice(states)
            danger = random.choice(dangers)
            self.download_entries.append({
                "id": i + 1,
                "url": url,
                "filename": filename,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S") if state == "Completed" else "N/A",
                "size": f"{size:,} bytes",
                "state": state,
                "danger": danger,
                "browser": browser_name
            })
        self.history_entries.sort(key=lambda x: x["last_visit"], reverse=True)
        self._populate_all()
        self._generate_stats()
        self.status_var.set(f"Simulated {browser_name}: {len(self.history_entries)} history, {len(self.cookie_entries)} cookies, {len(self.download_entries)} downloads")

    def _populate_all(self):
        self._filter_history()
        for item in self.cookie_tree.get_children():
            self.cookie_tree.delete(item)
        for c in self.cookie_entries:
            self.cookie_tree.insert("", "end", values=(
                c["host"], c["name"], c["value"][:20] + "...", c["path"],
                c["expires"], c["secure"], c["http_only"], c["browser"]
            ))
        for item in self.dl_tree.get_children():
            self.dl_tree.delete(item)
        for d in self.download_entries:
            tag = "dangerous" if d["danger"] in ("High", "Medium") else "safe"
            self.dl_tree.insert("", "end", values=(
                d["id"], d["url"], d["filename"], d["start_time"],
                d["end_time"], d["size"], d["state"], d["danger"]
            ), tags=(tag,))

    def _filter_history(self):
        for item in self.hist_tree.get_children():
            self.hist_tree.delete(item)
        search = self.search_var.get().lower()
        count = 0
        for h in self.history_entries:
            if search and search not in h["url"].lower() and search not in h["title"].lower():
                continue
            self.hist_tree.insert("", "end", values=(
                h["id"], h["url"], h["title"], h["visit_count"],
                h["last_visit"], h["typed_count"], h["browser"]
            ))
            count += 1
        self.history_count_var.set(f"Visits: {count}")

    def _generate_stats(self):
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("end", "=" * 60 + "\n")
        self.stats_text.insert("end", "BROWSER ARTIFACT STATISTICS\n")
        self.stats_text.insert("end", "=" * 60 + "\n\n")
        self.stats_text.insert("end", f"History Entries: {len(self.history_entries)}\n")
        self.stats_text.insert("end", f"Cookies: {len(self.cookie_entries)}\n")
        self.stats_text.insert("end", f"Downloads: {len(self.download_entries)}\n\n")
        domain_counts = defaultdict(int)
        for h in self.history_entries:
            try:
                domain = h["url"].split("//")[1].split("/")[0]
                domain_counts[domain] += 1
            except:
                pass
        self.stats_text.insert("end", "Top Domains by Visits:\n")
        for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1])[:15]:
            bar = "#" * min(count, 40)
            self.stats_text.insert("end", f"  {domain:<35} {count:>4}  {bar}\n")
        self.stats_text.insert("end", "\nCookie Names:\n")
        cookie_name_counts = defaultdict(int)
        for c in self.cookie_entries:
            cookie_name_counts[c["name"]] += 1
        for name, count in sorted(cookie_name_counts.items(), key=lambda x: -x[1])[:10]:
            self.stats_text.insert("end", f"  {name:<25} {count:>4}\n")
        self.stats_text.insert("end", f"\nDownloads: {len(self.download_entries)}\n")
        danger_count = sum(1 for d in self.download_entries if d["danger"] in ("High", "Medium"))
        self.stats_text.insert("end", f"  Flagged as dangerous: {danger_count}\n")

    def _generate_report(self):
        if not self.history_entries:
            messagebox.showwarning("No Data", "No data to report.")
            return
        report = self._build_report_data()
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 80 + "\n")
        self.report_text.insert("end", "BROWSER ARTIFACT EXTRACTION REPORT\n")
        self.report_text.insert("end", "=" * 80 + "\n\n")
        self.report_text.insert("end", f"Generated: {report['metadata']['timestamp']}\n")
        self.report_text.insert("end", f"Browser: {report['metadata']['browser']}\n")
        self.report_text.insert("end", f"History: {report['metadata']['history_count']} | Cookies: {report['metadata']['cookie_count']} | Downloads: {report['metadata']['download_count']}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "BROWSING HISTORY (Top 50)\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for h in report["history"][:50]:
            self.report_text.insert("end", f"  {h['last_visit']}  {h['url'][:70]}  (visits: {h['visit_count']})\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "COOKIES (Top 30)\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for c in report["cookies"][:30]:
            self.report_text.insert("end", f"  {c['host']:<30} {c['name']:<20} secure={c['secure']} httpOnly={c['http_only']}\n")
        self.report_text.insert("end", "\n" + "-" * 80 + "\n")
        self.report_text.insert("end", "DOWNLOADS\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for d in report["downloads"]:
            flag = " [DANGEROUS]" if d["danger"] in ("High", "Medium") else ""
            self.report_text.insert("end", f"  {d['start_time']}  {d['filename']:<40} {d['state']}{flag}\n")
        self.status_var.set("Report generated")

    def _build_report_data(self):
        return {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "browser": self.loaded_browser or "Simulated",
                "history_count": len(self.history_entries),
                "cookie_count": len(self.cookie_entries),
                "download_count": len(self.download_entries),
                "tool": "Browser Artifact Extractor"
            },
            "history": self.history_entries,
            "cookies": self.cookie_entries,
            "downloads": self.download_entries
        }

    def _export(self, fmt):
        if not self.history_entries:
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
                    w.writerow(["ID", "URL", "Title", "Visits", "Last Visit", "Browser"])
                    for h in report["history"]:
                        w.writerow([h["id"], h["url"], h["title"], h["visit_count"], h["last_visit"], h["browser"]])
                    w.writerow([])
                    w.writerow(["Host", "Name", "Value", "Secure", "HttpOnly", "Browser"])
                    for c in report["cookies"]:
                        w.writerow([c["host"], c["name"], c["value"], c["secure"], c["http_only"], c["browser"]])
                    w.writerow([])
                    w.writerow(["ID", "URL", "Filename", "Started", "State", "Danger", "Browser"])
                    for d in report["downloads"]:
                        w.writerow([d["id"], d["url"], d["filename"], d["start_time"], d["state"], d["danger"], d["browser"]])
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("BROWSER ARTIFACT EXTRACTION REPORT\n")
                    f.write(f"Generated: {report['metadata']['timestamp']}\n\n")
                    f.write(f"HISTORY ({report['metadata']['history_count']}):\n")
                    for h in report["history"]:
                        f.write(f"  {h['last_visit']}  {h['url']}\n")
                    f.write(f"\nCOOKIES ({report['metadata']['cookie_count']}):\n")
                    for c in report["cookies"]:
                        f.write(f"  {c['host']}  {c['name']}\n")
                    f.write(f"\nDOWNLOADS ({report['metadata']['download_count']}):\n")
                    for d in report["downloads"]:
                        f.write(f"  {d['start_time']}  {d['filename']}  {d['state']}  {d['danger']}\n")
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("<!DOCTYPE html><html><head><title>Browser Artifact Report</title>")
                    f.write(f"<style>body{{font-family:monospace;background:{BG};color:{TEXT};padding:20px}}")
                    f.write(f"h1{{color:{PRIMARY}}}h2{{color:{SUCCESS}}}table{{border-collapse:collapse;width:100%}}")
                    f.write(f"th{{background:{SURFACE2};color:{PRIMARY};padding:8px;text-align:left}}")
                    f.write(f"td{{padding:6px;border-bottom:1px solid {BORDER}}}")
                    f.write(f".dangerous{{color:{DANGER}}}.safe{{color:{SUCCESS}}}</style></head><body>")
                    f.write(f"<h1>Browser Artifact Report</h1>")
                    f.write(f"<p>Generated: {report['metadata']['timestamp']}</p>")
                    f.write("<h2>Browsing History (Top 50)</h2><table><tr><th>URL</th><th>Title</th><th>Visits</th><th>Last Visit</th></tr>")
                    for h in report["history"][:50]:
                        f.write(f"<tr><td>{h['url'][:80]}</td><td>{h['title'][:40]}</td><td>{h['visit_count']}</td><td>{h['last_visit']}</td></tr>")
                    f.write("</table><h2>Cookies</h2><table><tr><th>Host</th><th>Name</th><th>Secure</th><th>HttpOnly</th></tr>")
                    for c in report["cookies"][:50]:
                        f.write(f"<tr><td>{c['host']}</td><td>{c['name']}</td><td>{c['secure']}</td><td>{c['http_only']}</td></tr>")
                    f.write("</table><h2>Downloads</h2><table><tr><th>Filename</th><th>State</th><th>Danger</th><th>Started</th></tr>")
                    for d in report["downloads"]:
                        cls = "dangerous" if d["danger"] in ("High", "Medium") else "safe"
                        f.write(f"<tr><td class='{cls}'>{d['filename']}</td><td>{d['state']}</td><td class='{cls}'>{d['danger']}</td><td>{d['start_time']}</td></tr>")
                    f.write("</table></body></html>")
            self.status_var.set(f"Report exported as {path}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        self.history_entries = []
        self.cookie_entries = []
        self.download_entries = []
        self.loaded_browser = None
        self.search_var.set("")
        for tree in [self.hist_tree, self.cookie_tree, self.dl_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")
        self.stats_text.delete("1.0", "end")
        self.history_count_var.set("Visits: 0")
        self.status_var.set("Ready - No browser database loaded")

    def _export_report(self):
        self._generate_report()

if __name__ == "__main__":
    root = tk.Tk()
    app = BrowserArtifactExtractorApp(root)
    root.mainloop()
