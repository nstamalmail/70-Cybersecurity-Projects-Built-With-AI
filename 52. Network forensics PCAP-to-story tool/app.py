#!/usr/bin/env python3
"""
Network Forensics PCAP-to-Story Tool
Tool 52 - Parse PCAP metadata, reconstruct sessions, decode protocols, generate narrative
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import hashlib
import os
import time
import random
import threading
from datetime import datetime, timedelta
from collections import OrderedDict

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


class NetworkForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Forensics PCAP-to-Story Tool")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_styles()

        self.pcap_metadata = {}
        self.sessions = []
        self.protocol_events = []
        self.extracted_files = []
        self.story_timeline = []
        self.analysis_active = False

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

        # Radiobutton
        style.configure("TRadiobutton",
                        background=BG,
                        foreground=TEXT,
                        font=("Segoe UI", 10))
        style.map("TRadiobutton",
                  background=[("active", BG)])

    def _build_ui(self):
        # === TOP ACCENT STRIP ===
        strip = tk.Frame(self.root, bg=PRIMARY, height=4)
        strip.pack(fill="x")
        strip.pack_propagate(False)

        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(header, text="Network Forensics PCAP-to-Story Tool", style="Title.TLabel").pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_load_tab()
        self._build_sessions_tab()
        self._build_protocols_tab()
        self._build_extraction_tab()
        self._build_story_tab()
        self._build_report_tab()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _build_load_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" PCAP Load ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Load & Parse PCAP File", style="Title.TLabel").pack(anchor=tk.W)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Open PCAP File", style="Primary.TButton", command=self._load_pcap).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Simulate PCAP", command=self._simulate_pcap).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Clear", command=self._clear_pcap).pack(side=tk.LEFT)

        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(top, variable=self.progress_var, maximum=100, length=600).pack(anchor=tk.W, pady=(8, 4))
        self.status_label = ttk.Label(top, text="Ready - Load a PCAP file to begin analysis", style="TLabel")
        self.status_label.pack(anchor=tk.W)

        meta_frame = ttk.Frame(frame)
        meta_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.meta_tree = ttk.Treeview(meta_frame, columns=("Property", "Value"), show="headings", height=15)
        self.meta_tree.heading("Property", text="Property")
        self.meta_tree.heading("Value", text="Value")
        self.meta_tree.column("Property", width=250)
        self.meta_tree.pack(fill=tk.BOTH, expand=True)

    def _load_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files","*.pcap *.pcapng"),("All files","*.*")])
        if path:
            self._analyze_pcap(path)

    def _simulate_pcap(self):
        fake_path = f"capture_{random.randint(1000,9999)}.pcap"
        self._analyze_pcap(fake_path)

    def _analyze_pcap(self, path):
        self.pcap_metadata = {
            "File": os.path.basename(path),
            "File Size": f"{random.uniform(1.0, 500.0):.2f} MB",
            "Capture Duration": f"{random.randint(30, 3600)} seconds",
            "Packet Count": f"{random.randint(1000, 500000):,}",
            "Link Type": "Ethernet (DLT_EN10MB)",
            "Start Time": (datetime.now() - timedelta(hours=random.randint(1,48))).strftime("%Y-%m-%d %H:%M:%S"),
            "End Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Avg Packet Size": f"{random.randint(200, 1500)} bytes",
            "Protocols Detected": "Ethernet, IPv4, TCP, UDP, DNS, HTTP, TLS",
            "Unique Source IPs": str(random.randint(5, 100)),
            "Unique Dest IPs": str(random.randint(5, 100)),
            "TCP Streams": str(random.randint(10, 500)),
            "UDP Flows": str(random.randint(5, 200)),
            "DNS Queries": str(random.randint(50, 5000)),
            "HTTP Requests": str(random.randint(10, 1000)),
            "TLS Sessions": str(random.randint(5, 200)),
            "Anomalies Detected": str(random.randint(0, 15))
        }
        for item in self.meta_tree.get_children():
            self.meta_tree.delete(item)
        for k, v in self.pcap_metadata.items():
            self.meta_tree.insert("", "end", values=(k, v))
        self._simulate_analysis()

    def _simulate_analysis(self):
        self.status_label.configure(text="Parsing packets...")
        self.sessions = []
        self.protocol_events = []
        self.extracted_files = []
        self.story_timeline = []

        src_ips = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]
        dst_ips = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]

        for i in range(random.randint(15, 60)):
            src = random.choice(src_ips)
            dst = random.choice(dst_ips)
            proto = random.choice(["TCP", "UDP", "ICMP"])
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 53, 22, 25, 110, 3389, 8080])
            packets = random.randint(5, 500)
            self.sessions.append({
                "id": i+1, "src": src, "dst": dst, "proto": proto,
                "sport": sport, "dport": dport, "packets": packets,
                "bytes": packets * random.randint(100, 1500),
                "start": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).strftime("%H:%M:%S"),
                "duration": f"{random.uniform(0.1, 60):.2f}s",
                "status": random.choice(["Complete", "Reset", "Timeout", "Active"])
            })

        protocols = [
            ("HTTP", ["GET /index.html", "POST /api/login", "GET /images/logo.png", "PUT /upload", "DELETE /resource"]),
            ("DNS", ["Query: example.com A", "Query: evil.xyz MX", "Response: 93.184.216.34", "Query: malware.ru A"]),
            ("TLS", ["ClientHello TLSv1.3", "ServerHello Certificate", "ChangeCipherSpec", "ApplicationData"]),
            ("SMTP", ["EHLO mail.example.com", "MAIL FROM:<sender@test.com>", "RCPT TO:<victim@corp.com>"]),
            ("SSH", ["Key Exchange Init", "New Keys", "Encrypted Packet"])
        ]
        for i in range(random.randint(30, 100)):
            proto, msgs = random.choice(protocols)
            self.protocol_events.append({
                "id": i+1, "time": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).strftime("%H:%M:%S.%f")[:12],
                "protocol": proto, "src": random.choice(src_ips), "dst": random.choice(dst_ips),
                "info": random.choice(msgs), "length": random.randint(40, 8000),
                "notes": ""
            })

        file_types = [
            ("executable", ".exe", "PE32 executable"),
            ("document", ".pdf", "PDF document"),
            ("archive", ".zip", "Zip archive"),
            ("image", ".jpg", "JPEG image"),
            ("script", ".ps1", "PowerShell script"),
            ("dll", ".dll", "Dynamic Link Library")
        ]
        for i in range(random.randint(3, 12)):
            ftype, ext, desc = random.choice(file_types)
            self.extracted_files.append({
                "id": i+1, "filename": f"file_{random.randint(1000,9999)}{ext}",
                "type": ftype, "description": desc,
                "size": f"{random.uniform(1, 5000):.1f} KB",
                "hash_md5": hashlib.md5(str(random.random()).encode()).hexdigest(),
                "hash_sha256": hashlib.sha256(str(random.random()).encode()).hexdigest(),
                "src_ip": random.choice(src_ips), "dst_ip": random.choice(dst_ips),
                "extracted_from": f"TCP Stream {random.randint(1,50)}"
            })

        events = [
            ("Connection Established", "Internal host initiates outbound connection"),
            ("DNS Resolution", "Suspicious domain resolved to external IP"),
            ("TLS Handshake", "Encrypted tunnel established"),
            ("Data Transfer", "Large data transfer observed"),
            ("File Download", "Executable file downloaded"),
            ("C2 Communication", "Possible command and control beacon"),
            ("Lateral Movement", "Internal host connects to multiple hosts"),
            ("Data Exfiltration", "Outbound data transfer spike detected")
        ]
        for i, (title, desc) in enumerate(random.sample(events, min(6, len(events)))):
            self.story_timeline.append({
                "order": i+1, "time": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).strftime("%H:%M:%S"),
                "event": title, "description": desc,
                "severity": random.choice(["Info", "Low", "Medium", "High", "Critical"]),
                "source": random.choice(src_ips)
            })
        self.story_timeline.sort(key=lambda x: x["time"])

        self.status_label.configure(text=f"Analysis complete: {len(self.sessions)} sessions, {len(self.protocol_events)} events")
        self.status_var.set(f"Analysis complete: {len(self.sessions)} sessions, {len(self.protocol_events)} events")

    def _clear_pcap(self):
        self.pcap_metadata.clear()
        self.sessions.clear()
        self.protocol_events.clear()
        self.extracted_files.clear()
        self.story_timeline.clear()
        for item in self.meta_tree.get_children():
            self.meta_tree.delete(item)
        self.status_label.configure(text="Cleared")
        self.status_var.set("Ready")

    def _build_sessions_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Sessions ")
        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Session Reconstruction", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Refresh", command=self._refresh_sessions).pack(anchor=tk.W, pady=(8,0))
        self.session_tree = ttk.Treeview(frame, columns=("ID","Src","Dst","Proto","Sport","Dport","Packets","Bytes","Duration","Status"), show="headings", height=20)
        for col, w in [("ID",50),("Src",140),("Dst",140),("Proto",70),("Sport",70),("Dport",70),("Packets",80),("Bytes",80),("Duration",80),("Status",90)]:
            self.session_tree.heading(col, text=col)
            self.session_tree.column(col, width=w)
        self.session_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _refresh_sessions(self):
        for item in self.session_tree.get_children():
            self.session_tree.delete(item)
        for s in self.sessions:
            self.session_tree.insert("", "end", values=(s["id"],s["src"],s["dst"],s["proto"],s["sport"],s["dport"],s["packets"],s["bytes"],s["duration"],s["status"]))

    def _build_protocols_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Protocols ")
        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Protocol Decode Events", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Refresh", command=self._refresh_protocols).pack(anchor=tk.W, pady=(8,0))
        self.proto_tree = ttk.Treeview(frame, columns=("ID","Time","Protocol","Src","Dst","Info","Length"), show="headings", height=20)
        for col, w in [("ID",50),("Time",120),("Protocol",80),("Src",130),("Dst",130),("Info",350),("Length",80)]:
            self.proto_tree.heading(col, text=col)
            self.proto_tree.column(col, width=w)
        self.proto_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _refresh_protocols(self):
        for item in self.proto_tree.get_children():
            self.proto_tree.delete(item)
        for p in self.protocol_events:
            self.proto_tree.insert("", "end", values=(p["id"],p["time"],p["protocol"],p["src"],p["dst"],p["info"],p["length"]))

    def _build_extraction_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Extraction ")
        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="File Extraction Results", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Refresh", command=self._refresh_extraction).pack(anchor=tk.W, pady=(8,0))
        self.extract_tree = ttk.Treeview(frame, columns=("ID","Filename","Type","Description","Size","Src IP","SHA256"), show="headings", height=20)
        for col, w in [("ID",50),("Filename",180),("Type",90),("Description",160),("Size",90),("Src IP",130),("SHA256",300)]:
            self.extract_tree.heading(col, text=col)
            self.extract_tree.column(col, width=w)
        self.extract_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _refresh_extraction(self):
        for item in self.extract_tree.get_children():
            self.extract_tree.delete(item)
        for f in self.extracted_files:
            self.extract_tree.insert("", "end", values=(f["id"],f["filename"],f["type"],f["description"],f["size"],f["src_ip"],f["hash_sha256"][:32]+"..."))

    def _build_story_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Story ")
        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Narrative Timeline", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Refresh Narrative", style="Primary.TButton", command=self._refresh_story).pack(anchor=tk.W, pady=(8,0))
        self.story_text = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.story_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _refresh_story(self):
        self.story_text.delete("1.0", tk.END)
        self.story_text.insert(tk.END, "=" * 70 + "\n")
        self.story_text.insert(tk.END, "NETWORK FORENSICS NARRATIVE TIMELINE\n")
        self.story_text.insert(tk.END, "=" * 70 + "\n\n")
        if not self.story_timeline:
            self.story_text.insert(tk.END, "No timeline data. Load a PCAP file first.\n")
            return
        for entry in self.story_timeline:
            sev_marker = {"Critical": "!!!", "High": "!!", "Medium": "!", "Low": "~", "Info": "-"}.get(entry["severity"], "")
            self.story_text.insert(tk.END, f"[{entry['time']}] [{entry['severity'].upper()}] {sev_marker} {entry['event']}\n")
            self.story_text.insert(tk.END, f"  Source: {entry['source']}\n")
            self.story_text.insert(tk.END, f"  {entry['description']}\n\n")

    def _build_report_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Report ")
        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Export Analysis Report", style="Title.TLabel").pack(anchor=tk.W)
        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        for fmt, cmd in [("JSON", self._export_json), ("CSV", self._export_csv), ("TXT", self._export_txt), ("HTML", self._export_html)]:
            ttk.Button(btn_frame, text=f"Export {fmt}", style="Primary.TButton", command=cmd).pack(side=tk.LEFT, padx=(0, 5))
        self.report_preview = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._generate_preview()

    def _generate_preview(self):
        self.report_preview.delete("1.0", tk.END)
        self.report_preview.insert(tk.END, json.dumps(self._build_report_data(), indent=2, default=str))

    def _build_report_data(self):
        return {
            "report_type": "Network Forensics PCAP Analysis Report",
            "pcap_metadata": self.pcap_metadata,
            "session_summary": {"total": len(self.sessions), "protocols": list(set(s["proto"] for s in self.sessions))},
            "sessions": self.sessions,
            "protocol_events": self.protocol_events,
            "extracted_files": self.extracted_files,
            "story_timeline": self.story_timeline,
            "generated_at": datetime.now().isoformat()
        }

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self._build_report_data(), f, indent=2, default=str)
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if path:
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Section","ID","Details"])
                for s in self.sessions:
                    w.writerow(["Session", s["id"], f"{s['src']}:{s['sport']} -> {s['dst']}:{s['dport']} ({s['proto']})"])
                for p in self.protocol_events:
                    w.writerow(["Protocol", p["id"], f"{p['protocol']}: {p['info']}"])
                for e in self.extracted_files:
                    w.writerow(["Extraction", e["id"], f"{e['filename']} ({e['type']})"])
                for t in self.story_timeline:
                    w.writerow(["Timeline", t["order"], f"[{t['time']}] {t['event']}: {t['description']}"])
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if path:
            data = self._build_report_data()
            with open(path, 'w') as f:
                f.write("=" * 70 + "\nNETWORK FORENSICS PCAP ANALYSIS REPORT\n" + "=" * 70 + "\n\n")
                f.write("--- PCAP METADATA ---\n")
                for k, v in data['pcap_metadata'].items():
                    f.write(f"  {k}: {v}\n")
                f.write(f"\n--- SESSIONS ({len(data['sessions'])}) ---\n")
                for s in data['sessions']:
                    f.write(f"  [{s['id']}] {s['src']}:{s['sport']} -> {s['dst']}:{s['dport']} ({s['proto']}) - {s['packets']} pkts, {s['duration']}\n")
                f.write(f"\n--- EXTRACTED FILES ({len(data['extracted_files'])}) ---\n")
                for e in data['extracted_files']:
                    f.write(f"  {e['filename']} ({e['type']}) - {e['size']}\n")
                f.write("\n--- STORY TIMELINE ---\n")
                for t in data['story_timeline']:
                    f.write(f"  [{t['time']}] [{t['severity']}] {t['event']}: {t['description']}\n")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_html(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if path:
            data = self._build_report_data()
            html = f"""<!DOCTYPE html><html><head><title>Network Forensics Report</title>
            <style>body{{font-family:Arial,sans-serif;margin:20px;background:{BG};color:{TEXT}}}
            h1{{color:{SUCCESS}}}table{{border-collapse:collapse;width:100%;margin:10px 0}}
            th,td{{border:1px solid {BORDER};padding:6px;text-align:left}}th{{background:{SURFACE2};color:{SUCCESS}}}
            td{{background:{SURFACE2}}}.critical{{color:{DANGER}}}.high{{color:{WARNING}}}.medium{{color:{WARNING}}}</style></head><body>"""
            html += "<h1>Network Forensics PCAP Analysis Report</h1>"
            html += "<h2>PCAP Metadata</h2><table><tr><th>Property</th><th>Value</th></tr>"
            for k, v in data['pcap_metadata'].items():
                html += f"<tr><td>{k}</td><td>{v}</td></tr>"
            html += f"</table><h2>Sessions ({len(data['sessions'])})</h2>"
            html += "<table><tr><th>ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Status</th></tr>"
            for s in data['sessions']:
                html += f"<tr><td>{s['id']}</td><td>{s['src']}:{s['sport']}</td><td>{s['dst']}:{s['dport']}</td><td>{s['proto']}</td><td>{s['packets']}</td><td>{s['status']}</td></tr>"
            html += f"</table><h2>Story Timeline</h2><table><tr><th>Time</th><th>Severity</th><th>Event</th><th>Description</th></tr>"
            for t in data['story_timeline']:
                html += f"<tr><td>{t['time']}</td><td class='{t['severity'].lower()}'>{t['severity']}</td><td>{t['event']}</td><td>{t['description']}</td></tr>"
            html += "</table></body></html>"
            with open(path, 'w') as f:
                f.write(html)
            messagebox.showinfo("Exported", f"Report exported to {path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkForensicsApp(root)
    root.mainloop()
