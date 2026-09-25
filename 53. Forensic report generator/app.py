#!/usr/bin/env python3
"""
Forensic Report Generator
Tool 53 - Report authoring tool for forensic examiners
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


class ForensicReportGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Report Generator")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_styles()

        self.findings = []
        self.evidence_log = []
        self.exhibit_index = []
        self.custody_trail = []
        self.report_meta = {
            "title": "Forensic Examination Report",
            "case_number": f"FR-{random.randint(10000,99999)}",
            "examiner": "Dr. Jane Smith, EnCE, GCFE",
            "organization": "Digital Forensics Lab",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "classification": "CONFIDENTIAL",
            "version": "1.0"
        }
        self.current_finding_id = 0

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
        ttk.Label(header, text="Forensic Report Generator", style="Title.TLabel").pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_case_tab()
        self._build_findings_tab()
        self._build_evidence_tab()
        self._build_exhibits_tab()
        self._build_custody_tab()
        self._build_preview_tab()
        self._build_report_tab()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _build_case_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Case Info ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Case Information", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(10, 0))

        self.case_entries = {}
        fields = [
            ("Report Title:", "title"), ("Case Number:", "case_number"),
            ("Examiner:", "examiner"), ("Organization:", "organization"),
            ("Date:", "date"), ("Classification:", "classification")
        ]
        for i, (label, key) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=i//2, column=(i%2)*2, sticky=tk.W, padx=(10, 5), pady=4)
            entry = ttk.Entry(form, width=40)
            entry.insert(0, self.report_meta[key])
            entry.grid(row=i//2, column=(i%2)*2+1, padx=(0, 20), pady=4)
            self.case_entries[key] = entry

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="Save Case Info", style="Primary.TButton", command=self._save_case_info).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Load Case (JSON)", command=self._load_case_json).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Save Case (JSON)", command=self._save_case_json).pack(side=tk.LEFT)

        summary_frame = ttk.Frame(frame)
        summary_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        ttk.Label(summary_frame, text="Report Summary", style="Subtitle.TLabel").pack(anchor=tk.W)
        self.summary_text = scrolledtext.ScrolledText(summary_frame, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, height=8)
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        self.summary_text.insert(tk.END, "Enter executive summary of the forensic examination here...")

    def _save_case_info(self):
        for key, entry in self.case_entries.items():
            self.report_meta[key] = entry.get()
        messagebox.showinfo("Saved", "Case information updated")

    def _load_case_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if path:
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                self.report_meta.update(data)
                for key, entry in self.case_entries.items():
                    entry.delete(0, tk.END)
                    entry.insert(0, self.report_meta.get(key, ""))
                messagebox.showinfo("Loaded", "Case information loaded")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _save_case_json(self):
        self._save_case_info()
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self.report_meta, f, indent=2)
            messagebox.showinfo("Saved", f"Case saved to {path}")

    def _build_findings_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Findings ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Finding Editor", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(form, text="Title:").grid(row=0, column=0, sticky=tk.W, padx=(10, 5))
        self.finding_title = ttk.Entry(form, width=50)
        self.finding_title.grid(row=0, column=1, padx=(0, 10), columnspan=3, sticky=tk.EW)

        ttk.Label(form, text="Severity:").grid(row=1, column=0, sticky=tk.W, padx=(10, 5), pady=4)
        self.finding_severity = ttk.Combobox(form, values=["Critical", "High", "Medium", "Low", "Informational"], state="readonly", width=15)
        self.finding_severity.set("Medium")
        self.finding_severity.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=4)

        ttk.Label(form, text="Category:").grid(row=1, column=2, sticky=tk.W, padx=(10, 5), pady=4)
        self.finding_category = ttk.Combobox(form, values=["Malware", "Data Breach", "Unauthorized Access", "Policy Violation", "Data Integrity", "Network Anomaly", "Insider Threat"], state="readonly", width=20)
        self.finding_category.set("Malware")
        self.finding_category.grid(row=1, column=3, sticky=tk.W, padx=(0, 10), pady=4)

        ttk.Label(form, text="Narrative:").grid(row=2, column=0, sticky=tk.NW, padx=(10, 5), pady=4)
        self.finding_narrative = scrolledtext.ScrolledText(form, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, height=6, width=60)
        self.finding_narrative.grid(row=2, column=1, columnspan=3, sticky=tk.EW, padx=(0, 10), pady=4)

        ttk.Label(form, text="Evidence Refs:").grid(row=3, column=0, sticky=tk.W, padx=(10, 5))
        self.finding_refs = ttk.Entry(form, width=50)
        self.finding_refs.grid(row=3, column=1, columnspan=3, sticky=tk.EW, padx=(0, 10))

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Add Finding", style="Primary.TButton", command=self._add_finding).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Update Selected", command=self._update_finding).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Delete Selected", style="Danger.TButton", command=self._delete_finding).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Clear Form", command=self._clear_finding_form).pack(side=tk.LEFT)

        self.findings_tree = ttk.Treeview(frame, columns=("ID", "Title", "Severity", "Category", "Narrative Preview"), show="headings", height=10)
        for col, w in [("ID", 50), ("Title", 250), ("Severity", 100), ("Category", 150), ("Narrative Preview", 400)]:
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=w)
        self.findings_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_select)

    def _add_finding(self):
        title = self.finding_title.get().strip()
        narrative = self.finding_narrative.get("1.0", tk.END).strip()
        if not title or not narrative:
            messagebox.showwarning("Warning", "Title and narrative are required")
            return
        self.current_finding_id += 1
        finding = {
            "id": self.current_finding_id, "title": title,
            "severity": self.finding_severity.get(), "category": self.finding_category.get(),
            "narrative": narrative, "evidence_refs": self.finding_refs.get().strip(),
            "created": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self._refresh_findings_tree()
        self._clear_finding_form()
        self.status_var.set(f"Finding #{finding['id']} added")
        messagebox.showinfo("Added", f"Finding #{finding['id']} added")

    def _update_finding(self):
        sel = self.findings_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select a finding to update")
            return
        fid = int(self.findings_tree.item(sel[0], "values")[0])
        for f in self.findings:
            if f["id"] == fid:
                f["title"] = self.finding_title.get().strip()
                f["severity"] = self.finding_severity.get()
                f["category"] = self.finding_category.get()
                f["narrative"] = self.finding_narrative.get("1.0", tk.END).strip()
                f["evidence_refs"] = self.finding_refs.get().strip()
                break
        self._refresh_findings_tree()

    def _delete_finding(self):
        sel = self.findings_tree.selection()
        if not sel:
            return
        fid = int(self.findings_tree.item(sel[0], "values")[0])
        self.findings = [f for f in self.findings if f["id"] != fid]
        self._refresh_findings_tree()

    def _clear_finding_form(self):
        self.finding_title.delete(0, tk.END)
        self.finding_narrative.delete("1.0", tk.END)
        self.finding_refs.delete(0, tk.END)
        self.finding_severity.set("Medium")
        self.finding_category.set("Malware")

    def _on_finding_select(self, event):
        sel = self.findings_tree.selection()
        if not sel:
            return
        fid = int(self.findings_tree.item(sel[0], "values")[0])
        for f in self.findings:
            if f["id"] == fid:
                self._clear_finding_form()
                self.finding_title.insert(0, f["title"])
                self.finding_severity.set(f["severity"])
                self.finding_category.set(f["category"])
                self.finding_narrative.insert("1.0", f["narrative"])
                self.finding_refs.insert(0, f["evidence_refs"])
                break

    def _refresh_findings_tree(self):
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        for f in self.findings:
            preview = f["narrative"][:80] + "..." if len(f["narrative"]) > 80 else f["narrative"]
            self.findings_tree.insert("", "end", values=(f["id"], f["title"], f["severity"], f["category"], preview))

    def _build_evidence_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Evidence ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Evidence Log Management", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))

        labels = [("Evidence ID:", 0, 0), ("Description:", 0, 2), ("Type:", 1, 0), ("Source:", 1, 2), ("Hash:", 2, 0), ("Custodian:", 2, 2)]
        self.evidence_entries = {}
        for label, row, col in labels:
            ttk.Label(form, text=label).grid(row=row, column=col, sticky=tk.W, padx=(10, 5), pady=3)
            entry = ttk.Entry(form, width=35)
            entry.grid(row=row, column=col+1, padx=(0, 10), pady=3, sticky=tk.EW)
            key = label.rstrip(":").lower().replace(" ", "_")
            self.evidence_entries[key] = entry

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Add Evidence", style="Primary.TButton", command=self._add_evidence).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Delete Selected", style="Danger.TButton", command=self._delete_evidence).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Import Evidence List", command=self._import_evidence).pack(side=tk.LEFT)

        self.evidence_tree = ttk.Treeview(frame, columns=("ID","Description","Type","Source","Hash","Custodian","Date"), show="headings", height=12)
        for col, w in [("ID",80),("Description",250),("Type",100),("Source",150),("Hash",200),("Custodian",120),("Date",120)]:
            self.evidence_tree.heading(col, text=col)
            self.evidence_tree.column(col, width=w)
        self.evidence_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _add_evidence(self):
        eid = self.evidence_entries["evidence id"].get().strip()
        desc = self.evidence_entries["description"].get().strip()
        if not eid or not desc:
            messagebox.showwarning("Warning", "Evidence ID and Description required")
            return
        ev = {
            "id": eid, "description": desc,
            "type": self.evidence_entries["type"].get().strip(),
            "source": self.evidence_entries["source"].get().strip(),
            "hash": self.evidence_entries["hash"].get().strip() or hashlib.sha256(eid.encode()).hexdigest()[:16],
            "custodian": self.evidence_entries["custodian"].get().strip(),
            "date": datetime.now().strftime("%Y-%m-%d")
        }
        self.evidence_log.append(ev)
        self._refresh_evidence_tree()
        for e in self.evidence_entries.values():
            e.delete(0, tk.END)

    def _delete_evidence(self):
        sel = self.evidence_tree.selection()
        if not sel:
            return
        eid = self.evidence_tree.item(sel[0], "values")[0]
        self.evidence_log = [e for e in self.evidence_log if e["id"] != eid]
        self._refresh_evidence_tree()

    def _import_evidence(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("CSV","*.csv")])
        if not path:
            return
        try:
            if path.endswith('.json'):
                with open(path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for ev in data:
                        ev.setdefault("date", datetime.now().strftime("%Y-%m-%d"))
                        self.evidence_log.append(ev)
            else:
                with open(path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row.setdefault("date", datetime.now().strftime("%Y-%m-%d"))
                        self.evidence_log.append(row)
            self._refresh_evidence_tree()
            messagebox.showinfo("Imported", "Evidence list imported")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _refresh_evidence_tree(self):
        for item in self.evidence_tree.get_children():
            self.evidence_tree.delete(item)
        for e in self.evidence_log:
            self.evidence_tree.insert("", "end", values=(e.get("id",""),e.get("description",""),e.get("type",""),e.get("source",""),e.get("hash",""),e.get("custodian",""),e.get("date","")))

    def _build_exhibits_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Exhibits ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Exhibit Index", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))
        self.exhibit_entries = {}
        for i, (label, key) in enumerate([("Exhibit #:", "number"), ("Title:", "title"), ("Description:", "desc"), ("Page/Ref:", "ref")]):
            ttk.Label(form, text=label).grid(row=0, column=i*2, sticky=tk.W, padx=(10,5))
            entry = ttk.Entry(form, width=25)
            entry.grid(row=0, column=i*2+1, padx=(0,10))
            self.exhibit_entries[key] = entry

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Add Exhibit", style="Primary.TButton", command=self._add_exhibit).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Delete Selected", style="Danger.TButton", command=self._delete_exhibit).pack(side=tk.LEFT)

        self.exhibit_tree = ttk.Treeview(frame, columns=("Exhibit","Title","Description","Reference"), show="headings", height=15)
        for col, w in [("Exhibit",80),("Title",200),("Description",350),("Reference",150)]:
            self.exhibit_tree.heading(col, text=col)
            self.exhibit_tree.column(col, width=w)
        self.exhibit_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _add_exhibit(self):
        num = self.exhibit_entries["number"].get().strip()
        title = self.exhibit_entries["title"].get().strip()
        if not num or not title:
            messagebox.showwarning("Warning", "Exhibit number and title required")
            return
        self.exhibit_index.append({"number": num, "title": title, "description": self.exhibit_entries["desc"].get(), "ref": self.exhibit_entries["ref"].get()})
        self._refresh_exhibit_tree()
        for e in self.exhibit_entries.values():
            e.delete(0, tk.END)

    def _delete_exhibit(self):
        sel = self.exhibit_tree.selection()
        if not sel:
            return
        num = self.exhibit_tree.item(sel[0], "values")[0]
        self.exhibit_index = [e for e in self.exhibit_index if e["number"] != num]
        self._refresh_exhibit_tree()

    def _refresh_exhibit_tree(self):
        for item in self.exhibit_tree.get_children():
            self.exhibit_tree.delete(item)
        for e in self.exhibit_index:
            self.exhibit_tree.insert("", "end", values=(e["number"],e["title"],e["description"],e["ref"]))

    def _build_custody_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Custody ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Chain of Custody", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))
        self.custody_entries = {}
        for i, (label, key) in enumerate([("Evidence ID:", "eid"), ("Action:", "action"), ("From:", "from_person"), ("To:", "to_person"), ("Notes:", "notes")]):
            ttk.Label(form, text=label).grid(row=0, column=i*2, sticky=tk.W, padx=(5,3))
            entry = ttk.Entry(form, width=20)
            entry.grid(row=0, column=i*2+1, padx=(0,5))
            self.custody_entries[key] = entry

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Add Entry", style="Primary.TButton", command=self._add_custody).pack(side=tk.LEFT, padx=(0, 5))

        self.custody_tree = ttk.Treeview(frame, columns=("Time","Evidence","Action","From","To","Hash"), show="headings", height=15)
        for col, w in [("Time",160),("Evidence",100),("Action",150),("From",120),("To",120),("Hash",200)]:
            self.custody_tree.heading(col, text=col)
            self.custody_tree.column(col, width=w)
        self.custody_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _add_custody(self):
        eid = self.custody_entries["eid"].get().strip()
        action = self.custody_entries["action"].get().strip()
        if not eid or not action:
            messagebox.showwarning("Warning", "Evidence ID and Action required")
            return
        ts = datetime.now().isoformat()
        h = hashlib.sha256(f"{ts}{eid}{action}".encode()).hexdigest()[:16]
        entry = {"timestamp": ts, "eid": eid, "action": action,
                 "from": self.custody_entries["from_person"].get(),
                 "to": self.custody_entries["to_person"].get(),
                 "notes": self.custody_entries["notes"].get(), "hash": h}
        self.custody_trail.append(entry)
        self.custody_tree.insert("", "end", values=(ts,eid,action,entry["from"],entry["to"],h))
        for e in self.custody_entries.values():
            e.delete(0, tk.END)

    def _build_preview_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Preview ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Report Preview", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Generate Preview", style="Primary.TButton", command=self._generate_preview).pack(anchor=tk.W, pady=(8,0))

        self.preview_text = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _generate_preview(self):
        self.preview_text.delete("1.0", tk.END)
        report = self._build_full_report()
        self.preview_text.insert(tk.END, report)

    def _build_full_report(self):
        lines = []
        lines.append("=" * 70)
        lines.append(self.report_meta["title"].upper())
        lines.append("=" * 70)
        lines.append(f"\nCase Number: {self.report_meta['case_number']}")
        lines.append(f"Examiner: {self.report_meta['examiner']}")
        lines.append(f"Organization: {self.report_meta['organization']}")
        lines.append(f"Date: {self.report_meta['date']}")
        lines.append(f"Classification: {self.report_meta['classification']}")
        lines.append(f"\n{'='*70}\nEXECUTIVE SUMMARY\n{'='*70}")
        lines.append(self.summary_text.get("1.0", tk.END).strip())
        lines.append(f"\n{'='*70}\nFINDINGS ({len(self.findings)})\n{'='*70}")
        for f in self.findings:
            lines.append(f"\nFinding #{f['id']}: {f['title']}")
            lines.append(f"  Severity: {f['severity']} | Category: {f['category']}")
            lines.append(f"  Evidence: {f['evidence_refs']}")
            lines.append(f"  {f['narrative']}")
        lines.append(f"\n{'='*70}\nEVIDENCE LOG ({len(self.evidence_log)})\n{'='*70}")
        for e in self.evidence_log:
            lines.append(f"  [{e.get('id','')}] {e.get('description','')} ({e.get('type','')}) - Hash: {e.get('hash','')}")
        lines.append(f"\n{'='*70}\nEXHIBIT INDEX ({len(self.exhibit_index)})\n{'='*70}")
        for e in self.exhibit_index:
            lines.append(f"  Exhibit {e['number']}: {e['title']} - {e['description']} (Ref: {e['ref']})")
        lines.append(f"\n{'='*70}\nCHAIN OF CUSTODY ({len(self.custody_trail)})\n{'='*70}")
        for c in self.custody_trail:
            lines.append(f"  [{c['timestamp']}] {c['action']}: {c['eid']} | {c['from']} -> {c['to']}")
        return "\n".join(lines)

    def _build_report_data(self):
        return {
            "report_meta": self.report_meta,
            "executive_summary": self.summary_text.get("1.0", tk.END).strip(),
            "findings": self.findings,
            "evidence_log": self.evidence_log,
            "exhibit_index": self.exhibit_index,
            "chain_of_custody": self.custody_trail,
            "generated_at": datetime.now().isoformat()
        }

    def _build_report_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Export ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Export Report", style="Title.TLabel").pack(anchor=tk.W)
        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        for fmt, cmd in [("JSON", self._export_json), ("CSV", self._export_csv), ("TXT", self._export_txt), ("HTML", self._export_html)]:
            ttk.Button(btn_frame, text=f"Export {fmt}", style="Primary.TButton", command=cmd).pack(side=tk.LEFT, padx=(0, 5))

        self.export_preview = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.export_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.export_preview.insert(tk.END, "Click a button above to export the report in the desired format.")

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self._build_report_data(), f, indent=2)
            self.export_preview.delete("1.0", tk.END)
            self.export_preview.insert(tk.END, f"Report exported to {path}\n\nFormat: JSON\nSize: {os.path.getsize(path)} bytes")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if path:
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Section", "Field", "Value"])
                for k, v in self.report_meta.items():
                    w.writerow(["Case Info", k, v])
                for fnd in self.findings:
                    w.writerow(["Finding", fnd["title"], f"{fnd['severity']}: {fnd['narrative'][:100]}"])
                for ev in self.evidence_log:
                    w.writerow(["Evidence", ev.get("id",""), ev.get("description","")])
                for ex in self.exhibit_index:
                    w.writerow(["Exhibit", ex["number"], ex["title"]])
            self.export_preview.delete("1.0", tk.END)
            self.export_preview.insert(tk.END, f"Report exported to {path}\n\nFormat: CSV")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if path:
            with open(path, 'w') as f:
                f.write(self._build_full_report())
            self.export_preview.delete("1.0", tk.END)
            self.export_preview.insert(tk.END, f"Report exported to {path}\n\nFormat: TXT")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_html(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if path:
            meta = self.report_meta
            css = (
                f"body{{font-family:Arial,sans-serif;margin:20px;background:{BG};color:{TEXT}}}"
                f"h1,h2{{color:{PRIMARY}}}table{{border-collapse:collapse;width:100%;margin:10px 0}}"
                f"th,td{{border:1px solid {BORDER};padding:6px;text-align:left}}"
                f"th{{background:{SURFACE2};color:{PRIMARY}}}td{{background:{SURFACE2}}}"
                f".critical{{color:{DANGER}}}.high{{color:{WARNING}}}.medium{{color:{WARNING}}}"
            )
            html = f"""<!DOCTYPE html><html><head><title>{meta['title']}</title>
            <style>{css}</style></head><body>"""
            html += f"<h1>{meta['title']}</h1>"
            html += f"<p><strong>Case:</strong> {meta['case_number']} | <strong>Examiner:</strong> {meta['examiner']} | <strong>Date:</strong> {meta['date']}</p>"
            html += f"<p><strong>Classification:</strong> {meta['classification']}</p>"
            html += f"<h2>Executive Summary</h2><p>{self.summary_text.get('1.0', tk.END).strip()}</p>"
            html += f"<h2>Findings ({len(self.findings)})</h2><table><tr><th>#</th><th>Title</th><th>Severity</th><th>Category</th><th>Narrative</th></tr>"
            for f in self.findings:
                html += f"<tr><td>{f['id']}</td><td>{f['title']}</td><td class='{f['severity'].lower()}'>{f['severity']}</td><td>{f['category']}</td><td>{f['narrative'][:150]}</td></tr>"
            html += f"</table><h2>Evidence Log ({len(self.evidence_log)})</h2><table><tr><th>ID</th><th>Description</th><th>Type</th><th>Hash</th></tr>"
            for e in self.evidence_log:
                html += f"<tr><td>{e.get('id','')}</td><td>{e.get('description','')}</td><td>{e.get('type','')}</td><td>{e.get('hash','')}</td></tr>"
            html += f"</table><h2>Chain of Custody ({len(self.custody_trail)})</h2><table><tr><th>Time</th><th>Evidence</th><th>Action</th><th>From</th><th>To</th></tr>"
            for c in self.custody_trail:
                html += f"<tr><td>{c['timestamp']}</td><td>{c['eid']}</td><td>{c['action']}</td><td>{c['from']}</td><td>{c['to']}</td></tr>"
            html += "</table></body></html>"
            with open(path, 'w') as f:
                f.write(html)
            self.export_preview.delete("1.0", tk.END)
            self.export_preview.insert(tk.END, f"Report exported to {path}\n\nFormat: HTML")
            messagebox.showinfo("Exported", f"Report exported to {path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicReportGenerator(root)
    root.mainloop()
