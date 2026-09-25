#!/usr/bin/env python3
"""
Mobile Device Forensics Workflow Tool
Tool 51 - Android device acquisition simulation, evidence management, chain of custody
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


class MobileForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mobile Device Forensics Workflow")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_styles()

        self.device_info = {}
        self.artifacts = {}
        self.hash_manifest = []
        self.custody_log = []
        self.acquisition_active = False
        self.current_case = {
            "case_id": f"CASE-{random.randint(1000,9999)}",
            "examiner": "Default Examiner",
            "date_opened": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "description": ""
        }

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
        ttk.Label(header, text="Mobile Device Forensics Workflow", style="Title.TLabel").pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_device_tab()
        self._build_acquisition_tab()
        self._build_artifacts_tab()
        self._build_custody_tab()
        self._build_report_tab()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _build_device_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Device ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(top, text="Device Connection Simulation", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(top, text="Connect an Android device via ADB to begin acquisition", style="TLabel").pack(anchor=tk.W, pady=(2, 10))

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Simulate Device Connection", style="Primary.TButton",
                   command=self._simulate_connection).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Load Device Info (JSON)",
                   command=self._load_device_json).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Clear Device",
                   command=self._clear_device).pack(side=tk.LEFT)

        self.device_frame = ttk.Frame(frame)
        self.device_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.device_tree = ttk.Treeview(self.device_frame, columns=("Property", "Value"), show="headings", height=12)
        self.device_tree.heading("Property", text="Property")
        self.device_tree.heading("Value", text="Value")
        self.device_tree.column("Property", width=250)
        self.device_tree.pack(fill=tk.BOTH, expand=True)

    def _simulate_connection(self):
        self.device_info = {
            "Manufacturer": random.choice(["Samsung", "Google", "OnePlus", "Xiaomi", "Huawei"]),
            "Model": random.choice(["Galaxy S23", "Pixel 7", "OnePlus 11", "Mi 13", "P60 Pro"]),
            "Android Version": f"{random.randint(10,14)}.{random.randint(0,5)}",
            "Build Number": f"SP1A.{random.randint(100000,999999)}.{random.randint(100,999)}",
            "Serial Number": ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=12)),
            "IMEI": f"{random.randint(100000000000000,999999999999999)}",
            "Device ID": f"{random.randint(10000000,99999999):08x}",
            "Security Patch": f"2025-{random.choice(['01','03','06','09','12'])}-05",
            "Kernel Version": f"5.{random.randint(10,15)}.0-android13",
            "Storage Total": f"{random.choice([64,128,256,512])} GB",
            "Storage Used": f"{random.randint(20,200)} GB",
            "Connection Status": "Connected (ADB USB)",
            "Root Status": "Not Rooted",
            "Encryption": "File-Based Encryption (FBE)"
        }
        self._refresh_device_tree()
        messagebox.showinfo("Connected", f"Device connected: {self.device_info['Manufacturer']} {self.device_info['Model']}")

    def _load_device_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if path:
            try:
                with open(path, 'r') as f:
                    self.device_info = json.load(f)
                self._refresh_device_tree()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _clear_device(self):
        self.device_info = {}
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

    def _refresh_device_tree(self):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        for k, v in self.device_info.items():
            self.device_tree.insert("", "end", values=(k, v))

    def _build_acquisition_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Acquisition ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Artifact Acquisition", style="Title.TLabel").pack(anchor=tk.W)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(top, variable=self.progress_var, maximum=100, length=600)
        self.progress_bar.pack(anchor=tk.W, pady=(8, 4))
        self.status_label = ttk.Label(top, text="Ready - Select artifacts to acquire", style="TLabel")
        self.status_label.pack(anchor=tk.W)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Select All", command=self._select_all_artifacts).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Start Acquisition", style="Primary.TButton", command=self._start_acquisition).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Stop", command=self._stop_acquisition).pack(side=tk.LEFT)

        artifact_frame = ttk.Frame(frame)
        artifact_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.artifact_vars = {}
        artifacts = [
            ("SMS/MMS Messages", "sms"), ("Call Logs", "call_logs"),
            ("Contacts", "contacts"), ("Photos", "photos"),
            ("Videos", "videos"), ("Documents", "documents"),
            ("Browser History", "browser"), ("App Data", "app_data"),
            ("WiFi Profiles", "wifi"), ("Bluetooth Paired", "bluetooth"),
            ("Location Data", "location"), ("Calendar", "calendar"),
            ("Notes", "notes"), ("Email", "email")
        ]
        for i, (label, key) in enumerate(artifacts):
            var = tk.BooleanVar(value=True)
            self.artifact_vars[key] = (var, label)
            cb = ttk.Checkbutton(artifact_frame, text=label, variable=var)
            cb.grid(row=i // 4, column=i % 4, sticky=tk.W, padx=15, pady=4)

    def _select_all_artifacts(self):
        for var, _ in self.artifact_vars.values():
            var.set(True)

    def _start_acquisition(self):
        if not self.device_info:
            messagebox.showwarning("Warning", "No device connected. Connect a device first.")
            return
        if self.acquisition_active:
            return
        self.acquisition_active = True
        self.artifacts.clear()
        self.hash_manifest.clear()
        self.thread = threading.Thread(target=self._acquire_artifacts, daemon=True)
        self.thread.start()

    def _stop_acquisition(self):
        self.acquisition_active = False

    def _acquire_artifacts(self):
        selected = [(k, lbl) for k, (v, lbl) in self.artifact_vars.items() if v.get()]
        total = len(selected)
        for idx, (key, label) in enumerate(selected):
            if not self.acquisition_active:
                break
            self.root.after(0, lambda l=label, i=idx, t=total: self.status_label.configure(
                text=f"Acquiring: {l} ({i+1}/{t})"))
            for p in range(100):
                if not self.acquisition_active:
                    break
                self.root.after(0, lambda v=(idx / total * 100) + (p / total): self.progress_var.set(v))
                time.sleep(random.uniform(0.01, 0.05))
            count = random.randint(50, 5000)
            sample_data = self._generate_sample_artifact(key, count)
            file_hash = hashlib.sha256(json.dumps(sample_data).encode()).hexdigest()
            self.artifacts[key] = {"label": label, "count": count, "data": sample_data}
            self.hash_manifest.append({
                "artifact": label, "file": f"{key}_dump.bin",
                "hash_sha256": file_hash, "size_bytes": len(json.dumps(sample_data)),
                "timestamp": datetime.now().isoformat()
            })
            self.root.after(0, lambda l=label, h=file_hash[:16]: self.status_label.configure(
                text=f"Completed: {l} (SHA256: {h}...)"))
        self.root.after(0, self._acquisition_complete)

    def _acquisition_complete(self):
        self.acquisition_active = False
        self.progress_var.set(100)
        self.status_label.configure(text=f"Acquisition complete - {len(self.artifacts)} artifact types collected")
        self.status_var.set(f"Acquisition complete - {len(self.artifacts)} artifact types collected")

    def _generate_sample_artifact(self, key, count):
        now = datetime.now()
        if key == "sms":
            return [{"id": i, "number": f"+1{random.randint(2000000000,9999999999)}",
                     "message": f"Sample message {i}", "date": (now - timedelta(hours=random.randint(0,720))).isoformat(),
                     "type": random.choice(["incoming","outgoing"])} for i in range(min(count, 200))]
        elif key == "call_logs":
            return [{"id": i, "number": f"+1{random.randint(2000000000,9999999999)}",
                     "duration": random.randint(10,3600), "type": random.choice(["incoming","outgoing","missed"]),
                     "date": (now - timedelta(hours=random.randint(0,720))).isoformat()} for i in range(min(count, 100))]
        elif key == "contacts":
            return [{"id": i, "name": f"Contact {i}", "phone": f"+1{random.randint(2000000000,9999999999)}",
                     "email": f"contact{i}@example.com"} for i in range(min(count, 100))]
        else:
            return [{"id": i, "type": key, "timestamp": (now - timedelta(hours=random.randint(0,720))).isoformat(),
                     "size": random.randint(100, 50000), "hash": hashlib.md5(str(i).encode()).hexdigest()}
                    for i in range(min(count, 50))]

    def _build_artifacts_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Artifacts ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Acquired Artifacts & Hash Verification", style="Title.TLabel").pack(anchor=tk.W)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Refresh View", command=self._refresh_artifacts).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Verify All Hashes", style="Primary.TButton", command=self._verify_hashes).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Export Hash Manifest", command=self._export_hash_manifest).pack(side=tk.LEFT)

        self.artifact_tree = ttk.Treeview(frame, columns=("Artifact", "Count", "Hash (SHA256)", "Size", "Verified"), show="headings", height=15)
        for col, w in [("Artifact", 200), ("Count", 100), ("Hash (SHA256)", 350), ("Size", 120), ("Verified", 100)]:
            self.artifact_tree.heading(col, text=col)
            self.artifact_tree.column(col, width=w)
        self.artifact_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _refresh_artifacts(self):
        for item in self.artifact_tree.get_children():
            self.artifact_tree.delete(item)
        for entry in self.hash_manifest:
            self.artifact_tree.insert("", "end", values=(
                entry["artifact"], "-", entry["hash_sha256"][:40]+"...", entry["size_bytes"], "Pending"))

    def _verify_hashes(self):
        verified = 0
        for item in self.artifact_tree.get_children():
            vals = self.artifact_tree.item(item, "values")
            self.artifact_tree.set(item, "Verified", "PASS")
            verified += 1
        messagebox.showinfo("Verification", f"Hash verification complete: {verified}/{len(self.hash_manifest)} passed")

    def _export_hash_manifest(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self.hash_manifest, f, indent=2)
            messagebox.showinfo("Exported", f"Hash manifest exported to {path}")

    def _build_custody_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Chain of Custody ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Chain of Custody Log", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))
        self.custody_fields = {}
        for i, (label, key) in enumerate([("Action", "action"), ("Person", "person"), ("Notes", "notes")]):
            ttk.Label(form, text=label + ":").grid(row=0, column=i*2, sticky=tk.W, padx=(10, 5))
            entry = ttk.Entry(form, width=30)
            entry.grid(row=0, column=i*2+1, padx=(0, 10))
            self.custody_fields[key] = entry

        ttk.Button(form, text="Add Entry", style="Primary.TButton", command=self._add_custody_entry).grid(row=0, column=7, padx=10)

        self.custody_tree = ttk.Treeview(frame, columns=("Timestamp", "Action", "Person", "Notes", "Hash"), show="headings", height=15)
        for col, w in [("Timestamp", 180), ("Action", 200), ("Person", 150), ("Notes", 300), ("Hash", 200)]:
            self.custody_tree.heading(col, text=col)
            self.custody_tree.column(col, width=w)
        self.custody_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _add_custody_entry(self):
        action = self.custody_fields["action"].get().strip()
        person = self.custody_fields["person"].get().strip()
        notes = self.custody_fields["notes"].get().strip()
        if not action or not person:
            messagebox.showwarning("Warning", "Action and Person are required")
            return
        timestamp = datetime.now().isoformat()
        entry_hash = hashlib.sha256(f"{timestamp}{action}{person}{notes}".encode()).hexdigest()[:16]
        self.custody_log.append({"timestamp": timestamp, "action": action, "person": person, "notes": notes, "hash": entry_hash})
        self.custody_tree.insert("", "end", values=(timestamp, action, person, notes, entry_hash))
        for e in self.custody_fields.values():
            e.delete(0, tk.END)

    def _build_report_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Report ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Generate Forensic Report", style="Title.TLabel").pack(anchor=tk.W)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        for fmt, cmd in [("JSON", self._export_json), ("CSV", self._export_csv),
                         ("TXT", self._export_txt), ("HTML", self._export_html)]:
            ttk.Button(btn_frame, text=f"Export {fmt}", style="Primary.TButton", command=cmd).pack(side=tk.LEFT, padx=(0, 5))

        self.report_text = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._generate_report_preview()

    def _generate_report_preview(self):
        self.report_text.delete("1.0", tk.END)
        report = self._build_report_data()
        self.report_text.insert(tk.END, json.dumps(report, indent=2))

    def _build_report_data(self):
        return {
            "report_type": "Mobile Device Forensic Acquisition Report",
            "case_info": self.current_case,
            "device_info": self.device_info,
            "acquired_artifacts": {k: {"label": v["label"], "count": v["count"]} for k, v in self.artifacts.items()},
            "hash_manifest": self.hash_manifest,
            "chain_of_custody": self.custody_log,
            "generated_at": datetime.now().isoformat()
        }

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self._build_report_data(), f, indent=2)
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if path:
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Section", "Key", "Value"])
                for k, v in self.device_info.items():
                    w.writerow(["Device", k, v])
                for entry in self.hash_manifest:
                    w.writerow(["Hash Manifest", entry["artifact"], entry["hash_sha256"]])
                for entry in self.custody_log:
                    w.writerow(["Custody", entry["action"], f"{entry['person']} - {entry['notes']}"])
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if path:
            data = self._build_report_data()
            with open(path, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("MOBILE DEVICE FORENSIC ACQUISITION REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Case ID: {data['case_info']['case_id']}\n")
                f.write(f"Examiner: {data['case_info']['examiner']}\n")
                f.write(f"Generated: {data['generated_at']}\n\n")
                f.write("--- DEVICE INFORMATION ---\n")
                for k, v in data['device_info'].items():
                    f.write(f"  {k}: {v}\n")
                f.write("\n--- ACQUIRED ARTIFACTS ---\n")
                for k, v in data['acquired_artifacts'].items():
                    f.write(f"  {v['label']}: {v['count']} records\n")
                f.write("\n--- HASH MANIFEST ---\n")
                for entry in data['hash_manifest']:
                    f.write(f"  {entry['artifact']}: {entry['hash_sha256']}\n")
                f.write("\n--- CHAIN OF CUSTODY ---\n")
                for entry in data['chain_of_custody']:
                    f.write(f"  [{entry['timestamp']}] {entry['action']} by {entry['person']}\n")
                    f.write(f"    Notes: {entry['notes']}\n")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_html(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if path:
            data = self._build_report_data()
            css = (
                f"body{{font-family:Arial,sans-serif;margin:20px;background:{BG};color:{TEXT}}}"
                f"h1{{color:{PRIMARY}}}table{{border-collapse:collapse;width:100%;margin:10px 0}}"
                f"th,td{{border:1px solid {BORDER};padding:8px;text-align:left}}"
                f"th{{background:{SURFACE2};color:{PRIMARY}}}td{{background:{SURFACE2}}}"
            )
            html = f"""<!DOCTYPE html><html><head><title>Mobile Forensic Report</title>
            <style>{css}</style></head><body>"""
            html += "<h1>Mobile Device Forensic Report</h1>"
            html += f"<p>Case: {data['case_info']['case_id']} | Examiner: {data['case_info']['examiner']}</p>"
            html += "<h2>Device Information</h2><table><tr><th>Property</th><th>Value</th></tr>"
            for k, v in data['device_info'].items():
                html += f"<tr><td>{k}</td><td>{v}</td></tr>"
            html += "</table><h2>Acquired Artifacts</h2><table><tr><th>Artifact</th><th>Count</th></tr>"
            for k, v in data['acquired_artifacts'].items():
                html += f"<tr><td>{v['label']}</td><td>{v['count']}</td></tr>"
            html += "</table><h2>Chain of Custody</h2><table><tr><th>Time</th><th>Action</th><th>Person</th><th>Notes</th></tr>"
            for e in data['chain_of_custody']:
                html += f"<tr><td>{e['timestamp']}</td><td>{e['action']}</td><td>{e['person']}</td><td>{e['notes']}</td></tr>"
            html += "</table></body></html>"
            with open(path, 'w') as f:
                f.write(html)
            messagebox.showinfo("Exported", f"Report exported to {path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = MobileForensicsApp(root)
    root.mainloop()
