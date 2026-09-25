#!/usr/bin/env python3
"""
Ransomware Tabletop Simulator + IR Runbook Builder
Tool 54 - Dual-mode: exercise simulator and runbook builder with NIST/CISA alignment
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


class RansomwareSimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Tabletop Simulator + IR Runbook Builder")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_styles()

        self.mode = "simulator"
        self.exercise = self._default_exercise()
        self.runbook = self._default_runbook()
        self.inject_library = self._build_inject_library()
        self.decisions_log = []
        self.action_items = []
        self.gap_analysis = []
        self.simulation_active = False
        self.current_phase_index = 0

        self._build_ui()

    def _default_exercise(self):
        return {
            "name": f"Exercise {datetime.now().strftime('%Y%m%d')}",
            "type": "Ransomware Tabletop",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "facilitator": "",
            "participants": [],
            "scenario": "",
            "phases": [],
            "status": "Draft"
        }

    def _default_runbook(self):
        return {
            "title": "Ransomware Incident Response Runbook",
            "version": "1.0",
            "aligned_to": ["NIST CSF", "CISA Ransomware Guide"],
            "sections": []
        }

    def _build_inject_library(self):
        return [
            {"id": "INJ-001", "phase": "Detection", "title": "Ransomware Alert", "description": "SIEM alerts on encryption activity detected on 3 workstations in accounting department.", "severity": "Critical"},
            {"id": "INJ-002", "phase": "Detection", "title": "User Report", "description": "Users report files on shared drive are inaccessible with .locked extension.", "severity": "High"},
            {"id": "INJ-003", "phase": "Escalation", "title": "Ransom Note Found", "description": "Ransom note found on infected systems demanding 50 BTC for decryption key.", "severity": "Critical"},
            {"id": "INJ-004", "phase": "Escalation", "title": "Media Inquiry", "description": "Journalist calls asking about potential data breach at the organization.", "severity": "High"},
            {"id": "INJ-005", "phase": "Decision", "title": "Payment Decision", "description": "Executive team asks whether to pay the ransom. Backup status unknown.", "severity": "Critical"},
            {"id": "INJ-006", "phase": "Decision", "title": "Law Enforcement", "description": "FBI contacts organization requesting information about the attack.", "severity": "Medium"},
            {"id": "INJ-007", "phase": "Recovery", "title": "Backup Restoration", "description": "IT team begins restoring from backups. Some backups may be compromised.", "severity": "High"},
            {"id": "INJ-008", "phase": "Recovery", "title": "System Rebuild", "description": "Critical systems need to be rebuilt from clean images. Timeline: 2-4 weeks.", "severity": "High"},
            {"id": "INJ-009", "phase": "Detection", "title": "Lateral Movement", "description": "Network monitoring shows attacker moving from accounting to HR systems.", "severity": "Critical"},
            {"id": "INJ-010", "phase": "Escalation", "title": "Regulatory Notification", "description": "Legal team determines GDPR/CCPA notification requirements within 72 hours.", "severity": "High"},
            {"id": "INJ-011", "phase": "Decision", "title": "Isolation Decision", "description": " debate on whether to isolate entire network or segment-by-segment containment.", "severity": "High"},
            {"id": "INJ-012", "phase": "Recovery", "title": "Clean Infrastructure", "description": "New clean servers provisioned. Decision needed on cloud vs on-prem rebuild.", "severity": "Medium"}
        ]

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
        ttk.Label(header, text="Ransomware Tabletop Simulator + IR Runbook Builder", style="Title.TLabel").pack(side=tk.LEFT)

        mode_frame = ttk.Frame(header)
        mode_frame.pack(side=tk.RIGHT)
        self.mode_var = tk.StringVar(value="simulator")
        ttk.Radiobutton(mode_frame, text="Tabletop Simulator", variable=self.mode_var, value="simulator",
                        command=self._switch_mode).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="IR Runbook Builder", variable=self.mode_var, value="runbook",
                        command=self._switch_mode).pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_exercise_tab()
        self._build_injects_tab()
        self._build_simulation_tab()
        self._build_runbook_tab()
        self._build_gap_tab()
        self._build_report_tab()

        self._switch_mode()

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _switch_mode(self):
        self.mode = self.mode_var.get()
        tabs = self.notebook.tabs()
        if self.mode == "simulator":
            for i in [0,1,2,4,5]:
                if i < len(tabs):
                    self.notebook.tab(i, state="normal")
            self.notebook.tab(3, state="hidden")
        else:
            for i in [0,1,2,4,5]:
                if i < len(tabs):
                    self.notebook.tab(i, state="hidden")
            self.notebook.tab(3, state="normal")
            self.notebook.tab(4, state="normal")
            self.notebook.tab(5, state="normal")

    def _build_exercise_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Exercise ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Exercise Configuration", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))

        self.ex_fields = {}
        for i, (label, key) in enumerate([("Exercise Name:", "name"), ("Facilitator:", "facilitator"), ("Date:", "date")]):
            ttk.Label(form, text=label).grid(row=i, column=0, sticky=tk.W, padx=(10,5), pady=3)
            entry = ttk.Entry(form, width=40)
            entry.insert(0, self.exercise.get(key, ""))
            entry.grid(row=i, column=1, padx=(0,20), pady=3)
            self.ex_fields[key] = entry

        ttk.Label(form, text="Scenario:").grid(row=0, column=2, sticky=tk.NW, padx=(10,5))
        self.scenario_text = scrolledtext.ScrolledText(form, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, width=60, height=6)
        self.scenario_text.grid(row=0, column=3, rowspan=3, padx=(0,10), pady=3, sticky=tk.NSEW)
        self.scenario_text.insert(tk.END, "A ransomware attack has been detected in the organization. Multiple systems are encrypted and a ransom note has been found. The attack vector appears to be a phishing email targeting the finance department.")

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Save Exercise", style="Primary.TButton", command=self._save_exercise).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Load Exercise", command=self._load_exercise).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Load Sample Exercise", style="Success.TButton", command=self._load_sample_exercise).pack(side=tk.LEFT, padx=(10,0))

    def _save_exercise(self):
        self.exercise["name"] = self.ex_fields["name"].get()
        self.exercise["facilitator"] = self.ex_fields["facilitator"].get()
        self.exercise["date"] = self.ex_fields["date"].get()
        self.exercise["scenario"] = self.scenario_text.get("1.0", tk.END).strip()
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump({"exercise": self.exercise, "decisions": self.decisions_log, "action_items": self.action_items}, f, indent=2)
            messagebox.showinfo("Saved", f"Exercise saved to {path}")

    def _load_exercise(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if path:
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                self.exercise = data.get("exercise", self._default_exercise())
                self.decisions_log = data.get("decisions", [])
                self.action_items = data.get("action_items", [])
                for key, entry in self.ex_fields.items():
                    entry.delete(0, tk.END)
                    entry.insert(0, self.exercise.get(key, ""))
                self.scenario_text.delete("1.0", tk.END)
                self.scenario_text.insert(tk.END, self.exercise.get("scenario", ""))
                messagebox.showinfo("Loaded", "Exercise loaded")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _load_sample_exercise(self):
        self.exercise["name"] = "Operation Lockdown - Ransomware TTX"
        self.exercise["facilitator"] = "CISO Office"
        self.exercise["scenario"] = ("On Monday morning, employees arriving at work found that critical systems including email, ERP, "
            "and file shares were inaccessible. Ransom notes appeared on screens demanding 100 BTC. Initial investigation reveals "
            "the attack originated from a phishing email sent to the CFO on Friday afternoon. Lateral movement has been detected "
            "across 3 VLANs. The threat actor claims to have exfiltrated 500GB of sensitive data.")
        self.exercise["phases"] = [
            {"name": "Detection", "injects": ["INJ-001","INJ-002","INJ-009"]},
            {"name": "Escalation", "injects": ["INJ-003","INJ-004","INJ-010"]},
            {"name": "Decision", "injects": ["INJ-005","INJ-006","INJ-011"]},
            {"name": "Recovery", "injects": ["INJ-007","INJ-008","INJ-012"]}
        ]
        for key, entry in self.ex_fields.items():
            entry.delete(0, tk.END)
            entry.insert(0, self.exercise.get(key, ""))
        self.scenario_text.delete("1.0", tk.END)
        self.scenario_text.insert(tk.END, self.exercise["scenario"])
        messagebox.showinfo("Loaded", "Sample exercise loaded")

    def _build_injects_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Injects ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Inject Library", style="Title.TLabel").pack(anchor=tk.W)

        self.inject_tree = ttk.Treeview(frame, columns=("ID","Phase","Title","Severity","Description"), show="headings", height=15)
        for col, w in [("ID",70),("Phase",100),("Title",200),("Severity",80),("Description",500)]:
            self.inject_tree.heading(col, text=col)
            self.inject_tree.column(col, width=w)
        self.inject_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._refresh_inject_tree()

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_frame, text="Add to Exercise", style="Primary.TButton", command=self._add_inject_to_exercise).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Create Custom Inject", command=self._create_custom_inject).pack(side=tk.LEFT)

    def _refresh_inject_tree(self):
        for item in self.inject_tree.get_children():
            self.inject_tree.delete(item)
        for inj in self.inject_library:
            self.inject_tree.insert("", "end", values=(inj["id"], inj["phase"], inj["title"], inj["severity"], inj["description"][:80]))

    def _add_inject_to_exercise(self):
        sel = self.inject_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select an inject to add")
            return
        inj_id = self.inject_tree.item(sel[0], "values")[0]
        messagebox.showinfo("Added", f"Inject {inj_id} added to exercise")

    def _create_custom_inject(self):
        custom = {
            "id": f"INJ-{random.randint(100,999)}",
            "phase": random.choice(["Detection","Escalation","Decision","Recovery"]),
            "title": "Custom Inject",
            "description": "Custom inject created by facilitator",
            "severity": "Medium"
        }
        self.inject_library.append(custom)
        self._refresh_inject_tree()

    def _build_simulation_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Simulation ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Live Simulation Control", style="Title.TLabel").pack(anchor=tk.W)

        self.sim_status_label = ttk.Label(top, text="Status: Not Started", style="TLabel")
        self.sim_status_label.pack(anchor=tk.W, pady=(5,0))

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_frame, text="Start Simulation", style="Success.TButton", command=self._start_simulation).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Inject Next", style="Primary.TButton", command=self._inject_next).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Stop", command=self._stop_simulation).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Record Decision", command=self._record_decision).pack(side=tk.LEFT)

        self.sim_log = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.sim_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _start_simulation(self):
        self.simulation_active = True
        self.current_phase_index = 0
        self.decisions_log.clear()
        self.action_items.clear()
        self.sim_log.delete("1.0", tk.END)
        self._log_sim("SIMULATION STARTED")
        self._log_sim(f"Exercise: {self.exercise.get('name', 'Untitled')}")
        self._log_sim(f"Scenario: {self.exercise.get('scenario', 'No scenario defined')[:200]}...")
        self._log_sim("-" * 60)
        self.sim_status_label.configure(text="Status: ACTIVE")
        self.status_var.set("Simulation ACTIVE")
        self.status_dot.configure(fg=SUCCESS)
        self._inject_next()

    def _inject_next(self):
        if not self.simulation_active:
            return
        if self.current_phase_index >= len(self.inject_library):
            self._log_sim("\nALL INJECTS DELIVERED")
            self._log_sim("Simulation complete. Review decisions and action items.")
            self.simulation_active = False
            self.sim_status_label.configure(text="Status: COMPLETE")
            self.status_var.set("Simulation COMPLETE")
            return
        inj = self.inject_library[self.current_phase_index]
        self._log_sim(f"\n[PHASE: {inj['phase'].upper()}] Inject {inj['id']}")
        self._log_sim(f"  Title: {inj['title']}")
        self._log_sim(f"  Severity: {inj['severity']}")
        self._log_sim(f"  {inj['description']}")
        self._log_sim("  -> RECORD YOUR TEAM'S DECISION")
        self.current_phase_index += 1

    def _stop_simulation(self):
        self.simulation_active = False
        self.sim_status_label.configure(text="Status: STOPPED")
        self.status_var.set("Simulation STOPPED")
        self._log_sim("\nSIMULATION STOPPED")

    def _record_decision(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Record Decision")
        dialog.geometry("500x300")
        dialog.configure(bg=BG)

        ttk.Label(dialog, text="Decision:").pack(anchor=tk.W, padx=10, pady=(10,2))
        decision_entry = tk.Text(dialog, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, height=4)
        decision_entry.pack(fill=tk.X, padx=10)

        ttk.Label(dialog, text="Action Items:").pack(anchor=tk.W, padx=10, pady=(5,2))
        action_entry = tk.Text(dialog, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, height=4)
        action_entry.pack(fill=tk.X, padx=10)

        def save_decision():
            d = decision_entry.get("1.0", tk.END).strip()
            a = action_entry.get("1.0", tk.END).strip()
            if d:
                self.decisions_log.append({"time": datetime.now().isoformat(), "decision": d, "phase": self.inject_library[min(self.current_phase_index-1, len(self.inject_library)-1)]["phase"]})
                self._log_sim(f"  DECISION: {d}")
                if a:
                    self.action_items.append({"time": datetime.now().isoformat(), "action": a, "status": "Open"})
                    self._log_sim(f"  ACTION: {a}")
                dialog.destroy()

        ttk.Button(dialog, text="Save", style="Primary.TButton", command=save_decision).pack(pady=10)

    def _log_sim(self, text):
        self.sim_log.insert(tk.END, text + "\n")
        self.sim_log.see(tk.END)

    def _build_runbook_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Runbook ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="IR Runbook Editor (NIST/CISA Aligned)", style="Title.TLabel").pack(anchor=tk.W)

        form = ttk.Frame(top)
        form.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(form, text="Title:").grid(row=0, column=0, sticky=tk.W, padx=(10,5))
        self.rb_title = ttk.Entry(form, width=50)
        self.rb_title.insert(0, self.runbook["title"])
        self.rb_title.grid(row=0, column=1, padx=(0,10))

        ttk.Label(form, text="Version:").grid(row=0, column=2, sticky=tk.W, padx=(10,5))
        self.rb_version = ttk.Entry(form, width=10)
        self.rb_version.insert(0, self.runbook["version"])
        self.rb_version.grid(row=0, column=3, padx=(0,10))

        self.nist_vars = {}
        nist_frames = ttk.Frame(top)
        nist_frames.pack(fill=tk.X, pady=(8,0))
        ttk.Label(nist_frames, text="NIST CSF Alignment:").pack(anchor=tk.W)
        for func in ["Identify", "Protect", "Detect", "Respond", "Recover"]:
            var = tk.BooleanVar(value=True)
            self.nist_vars[func] = var
            ttk.Checkbutton(nist_frames, text=func, variable=var).pack(side=tk.LEFT, padx=10)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8,0))
        ttk.Button(btn_frame, text="Add Runbook Section", style="Primary.TButton", command=self._add_runbook_section).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Load NIST Template", style="Success.TButton", command=self._load_nist_template).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="Validate Runbook", command=self._validate_runbook).pack(side=tk.LEFT)

        self.rb_sections_tree = ttk.Treeview(frame, columns=("Order","Title","Aligned To","Steps"), show="headings", height=15)
        for col, w in [("Order",60),("Title",250),("Aligned To",200),("Steps",400)]:
            self.rb_sections_tree.heading(col, text=col)
            self.rb_sections_tree.column(col, width=w)
        self.rb_sections_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._refresh_runbook_tree()

    def _add_runbook_section(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Runbook Section")
        dialog.geometry("500x350")
        dialog.configure(bg=BG)

        ttk.Label(dialog, text="Section Title:").pack(anchor=tk.W, padx=10, pady=(10,2))
        title_e = ttk.Entry(dialog, width=50)
        title_e.pack(fill=tk.X, padx=10)

        ttk.Label(dialog, text="Aligned To (comma-separated):").pack(anchor=tk.W, padx=10, pady=(5,2))
        aligned_e = ttk.Entry(dialog, width=50)
        aligned_e.insert(0, "NIST CSF Respond, CISA Ransomware Guide")
        aligned_e.pack(fill=tk.X, padx=10)

        ttk.Label(dialog, text="Steps:").pack(anchor=tk.W, padx=10, pady=(5,2))
        steps_t = tk.Text(dialog, bg=SURFACE2, fg=TEXT, font=("Segoe UI", 10), insertbackground=TEXT, height=8)
        steps_t.pack(fill=tk.X, padx=10)

        def save_section():
            t = title_e.get().strip()
            a = aligned_e.get().strip()
            s = steps_t.get("1.0", tk.END).strip()
            if t:
                self.runbook["sections"].append({"title": t, "aligned_to": a, "steps": s})
                self._refresh_runbook_tree()
                dialog.destroy()

        ttk.Button(dialog, text="Save Section", style="Primary.TButton", command=save_section).pack(pady=10)

    def _load_nist_template(self):
        self.runbook["sections"] = [
            {"title": "Preparation", "aligned_to": "NIST CSF Identify/Protect", "steps": "1. Maintain asset inventory\n2. Ensure backups are current\n3. Define roles and responsibilities\n4. Conduct security awareness training"},
            {"title": "Detection & Analysis", "aligned_to": "NIST CSF Detect", "steps": "1. Monitor SIEM alerts\n2. Analyze indicators of compromise\n3. Determine scope of compromise\n4. Document initial findings"},
            {"title": "Containment", "aligned_to": "NIST CSF Respond", "steps": "1. Isolate affected systems\n2. Block malicious IPs/domains\n3. Disable compromised accounts\n4. Preserve evidence for forensics"},
            {"title": "Eradication", "aligned_to": "NIST CSF Respond", "steps": "1. Remove malware from systems\n2. Patch exploited vulnerabilities\n3. Reset credentials\n4. Verify system integrity"},
            {"title": "Recovery", "aligned_to": "NIST CSF Recover", "steps": "1. Restore from clean backups\n2. Rebuild compromised systems\n3. Monitor for re-infection\n4. Gradually restore services"},
            {"title": "Post-Incident", "aligned_to": "NIST CSF Recover", "steps": "1. Conduct lessons learned\n2. Update runbook based on findings\n3. Report to stakeholders\n4. Implement preventive controls"}
        ]
        self._refresh_runbook_tree()
        messagebox.showinfo("Template Loaded", "NIST-aligned runbook template loaded")

    def _validate_runbook(self):
        issues = []
        if not self.runbook["sections"]:
            issues.append("No runbook sections defined")
        for i, sec in enumerate(self.runbook["sections"]):
            if not sec.get("steps"):
                issues.append(f"Section '{sec['title']}' has no steps")
            if not sec.get("aligned_to"):
                issues.append(f"Section '{sec['title']}' has no framework alignment")
        if not issues:
            messagebox.showinfo("Validation", "Runbook validation PASSED - all sections complete")
        else:
            messagebox.showwarning("Validation Issues", "\n".join(issues))

    def _refresh_runbook_tree(self):
        for item in self.rb_sections_tree.get_children():
            self.rb_sections_tree.delete(item)
        for i, sec in enumerate(self.runbook["sections"], 1):
            self.rb_sections_tree.insert("", "end", values=(i, sec["title"], sec["aligned_to"], sec["steps"][:100]))

    def _build_gap_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Gap Analysis ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Gap Analysis", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Button(top, text="Run Gap Analysis", style="Primary.TButton", command=self._run_gap_analysis).pack(anchor=tk.W, pady=(8,0))

        self.gap_tree = ttk.Treeview(frame, columns=("Category","Current State","Required","Gap","Recommendation"), show="headings", height=15)
        for col, w in [("Category",150),("Current State",200),("Required",200),("Gap",100),("Recommendation",300)]:
            self.gap_tree.heading(col, text=col)
            self.gap_tree.column(col, width=w)
        self.gap_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _run_gap_analysis(self):
        gaps = [
            ("Backup Strategy", "Weekly backups", "Daily immutable backups", "HIGH", "Implement daily immutable backup solution"),
            ("Network Segmentation", "Flat network", "Micro-segmentation", "HIGH", "Deploy network segmentation for critical assets"),
            ("Incident Response Plan", "Outdated (2022)", "Current, tested quarterly", "MEDIUM", "Update IR plan and schedule quarterly exercises"),
            ("Endpoint Detection", "Basic antivirus", "EDR with behavioral analysis", "HIGH", "Deploy EDR solution across all endpoints"),
            ("User Training", "Annual training", "Monthly phishing simulations", "MEDIUM", "Implement monthly security awareness program"),
            ("Patch Management", "Manual, irregular", "Automated within 48hrs", "HIGH", "Deploy automated patch management solution"),
            ("Privileged Access", "Local admin common", "PAM with MFA", "MEDIUM", "Implement PAM solution with MFA enforcement"),
            ("Threat Intelligence", "None", "Active threat feed integration", "MEDIUM", "Subscribe to threat intelligence feeds")
        ]
        self.gap_analysis = gaps
        for item in self.gap_tree.get_children():
            self.gap_tree.delete(item)
        for g in gaps:
            self.gap_tree.insert("", "end", values=g)
        self.status_var.set(f"Gap analysis complete: {len(gaps)} gaps identified")

    def _build_report_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=" Report ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Export Report", style="Title.TLabel").pack(anchor=tk.W)
        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, pady=(8,0))
        for fmt, cmd in [("JSON", self._export_json), ("CSV", self._export_csv), ("TXT", self._export_txt), ("HTML", self._export_html)]:
            ttk.Button(btn_frame, text=f"Export {fmt}", style="Primary.TButton", command=cmd).pack(side=tk.LEFT, padx=(0,5))

        self.report_preview = scrolledtext.ScrolledText(frame, bg=SURFACE2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT)
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._generate_report_preview()

    def _generate_report_preview(self):
        self.report_preview.delete("1.0", tk.END)
        data = self._build_report_data()
        self.report_preview.insert(tk.END, json.dumps(data, indent=2, default=str))

    def _build_report_data(self):
        return {
            "report_type": "Ransomware Tabletop Exercise Report",
            "mode": self.mode,
            "exercise": self.exercise,
            "decisions_log": self.decisions_log,
            "action_items": self.action_items,
            "runbook": self.runbook if self.mode == "runbook" else None,
            "gap_analysis": self.gap_analysis,
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
                w.writerow(["Section", "Item", "Details"])
                w.writerow(["Exercise", "Name", self.exercise.get("name","")])
                w.writerow(["Exercise", "Date", self.exercise.get("date","")])
                for d in self.decisions_log:
                    w.writerow(["Decision", d.get("time",""), d.get("decision","")])
                for a in self.action_items:
                    w.writerow(["Action Item", a.get("time",""), a.get("action","")])
                for g in self.gap_analysis:
                    w.writerow(["Gap", g[0], f"{g[2]} ({g[3]})"])
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if path:
            ex = self.exercise
            with open(path, 'w') as f:
                f.write("=" * 70 + "\nRANSOMWARE TABLETOP EXERCISE REPORT\n" + "=" * 70 + "\n\n")
                f.write(f"Exercise: {ex.get('name','')}\nDate: {ex.get('date','')}\nFacilitator: {ex.get('facilitator','')}\n")
                f.write(f"\nScenario:\n{ex.get('scenario','')}\n")
                f.write(f"\n--- DECISIONS ({len(self.decisions_log)}) ---\n")
                for d in self.decisions_log:
                    f.write(f"  [{d['time']}] {d['decision']}\n")
                f.write(f"\n--- ACTION ITEMS ({len(self.action_items)}) ---\n")
                for a in self.action_items:
                    f.write(f"  [{a['status']}] {a['action']}\n")
                if self.gap_analysis:
                    f.write("\n--- GAP ANALYSIS ---\n")
                    for g in self.gap_analysis:
                        f.write(f"  {g[0]}: {g[3]} - {g[4]}\n")
                if self.mode == "runbook" and self.runbook["sections"]:
                    f.write("\n--- IR RUNBOOK ---\n")
                    for i, sec in enumerate(self.runbook["sections"], 1):
                        f.write(f"\n  Section {i}: {sec['title']} ({sec['aligned_to']})\n")
                        f.write(f"  {sec['steps']}\n")
            messagebox.showinfo("Exported", f"Report exported to {path}")

    def _export_html(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if path:
            ex = self.exercise
            html = f"""<!DOCTYPE html><html><head><title>Ransomware Exercise Report</title>
            <style>body{{font-family:Arial,sans-serif;margin:20px;background:{BG};color:{TEXT}}}
            h1,h2{{color:{DANGER}}}table{{border-collapse:collapse;width:100%;margin:10px 0}}
            th,td{{border:1px solid {BORDER};padding:6px;text-align:left}}th{{background:{SURFACE2};color:{DANGER}}}
            td{{background:{SURFACE2}}}.high{{color:{DANGER}}}.medium{{color:{WARNING}}}.low{{color:{SUCCESS}}}</style></head><body>"""
            html += "<h1>Ransomware Tabletop Exercise Report</h1>"
            html += f"<p><strong>Exercise:</strong> {ex.get('name','')} | <strong>Date:</strong> {ex.get('date','')}</p>"
            html += f"<h2>Scenario</h2><p>{ex.get('scenario','')}</p>"
            html += f"<h2>Decisions ({len(self.decisions_log)})</h2><table><tr><th>Time</th><th>Decision</th></tr>"
            for d in self.decisions_log:
                html += f"<tr><td>{d['time']}</td><td>{d['decision']}</td></tr>"
            html += f"</table><h2>Action Items ({len(self.action_items)})</h2><table><tr><th>Status</th><th>Action</th></tr>"
            for a in self.action_items:
                html += f"<tr><td>{a['status']}</td><td>{a['action']}</td></tr>"
            html += f"</table><h2>Gap Analysis</h2><table><tr><th>Category</th><th>Current</th><th>Required</th><th>Gap</th><th>Recommendation</th></tr>"
            for g in self.gap_analysis:
                html += f"<tr><td>{g[0]}</td><td>{g[1]}</td><td>{g[2]}</td><td class='{g[3].lower()}'>{g[3]}</td><td>{g[4]}</td></tr>"
            html += "</table></body></html>"
            with open(path, 'w') as f:
                f.write(html)
            messagebox.showinfo("Exported", f"Report exported to {path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareSimulatorApp(root)
    root.mainloop()
