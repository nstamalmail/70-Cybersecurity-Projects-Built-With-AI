#!/usr/bin/env python3
"""
Forensic Image Acquisition & Hashing Toolkit (FAHT-GUI)
Bit-stream disk acquisition with cryptographic verification and chain-of-custody.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import threading
import os
import json
import time
import struct
import platform
import uuid
import datetime
import csv
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

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

@dataclass
class CaseMetadata:
    case_number: str = ""
    evidence_id: str = ""
    examiner_name: str = ""
    organization: str = ""
    notes: str = ""

@dataclass
class AcquisitionResult:
    source_path: str = ""
    output_path: str = ""
    image_format: str = "RAW"
    file_size: int = 0
    sha256_inline: str = ""
    sha256_post: str = ""
    sha512_inline: str = ""
    blake3_inline: str = ""
    hashes_match: bool = False
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0
    block_size: int = 65536
    bad_sectors: int = 0
    host_info: dict = field(default_factory=dict)
    status: str = "pending"

class HostTelemetry:
    @staticmethod
    def collect():
        return {
            "hostname": platform.node(),
            "os_version": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "processor": platform.processor(),
            "mac_address": str(uuid.getnode()),
            "python_version": platform.python_version(),
            "collection_time_utc": datetime.datetime.utcnow().isoformat(),
        }

class HashingEngine:
    @staticmethod
    def compute_file_hash(filepath, algorithm="sha256", callback=None, block_size=65536):
        h = hashlib.new(algorithm)
        total = os.path.getsize(filepath)
        read = 0
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
                if callback:
                    callback(read, total)
        return h.hexdigest()

    @staticmethod
    def compute_stream_hash(data_generator, algorithm="sha256", callback=None):
        h = hashlib.new(algorithm)
        total = 0
        for chunk in data_generator:
            h.update(chunk)
            total += len(chunk)
            if callback:
                callback(total, None)
        return h.hexdigest(), total

class AcquisitionEngine:
    def __init__(self, source, dest, block_size=65536, on_progress=None, on_complete=None):
        self.source = source
        self.dest = dest
        self.block_size = block_size
        self.on_progress = on_progress
        self.on_complete = on_complete
        self.cancelled = False
        self.result = AcquisitionResult()

    def cancel(self):
        self.cancelled = True

    def run(self):
        self.result.source_path = self.source
        self.result.output_path = self.dest
        self.result.block_size = self.block_size
        self.result.start_time = datetime.datetime.utcnow().isoformat()
        self.result.host_info = HostTelemetry.collect()
        self.result.status = "running"

        sha256_h = hashlib.sha256()
        sha512_h = hashlib.sha512()
        try:
            import blake3
            blake3_h = blake3.blake3()
            has_blake3 = True
        except ImportError:
            blake3_h = None
            has_blake3 = False

        total_size = os.path.getsize(self.source)
        written = 0

        try:
            with open(self.source, "rb") as src, open(self.dest, "wb") as dst:
                while not self.cancelled:
                    chunk = src.read(self.block_size)
                    if not chunk:
                        break
                    sha256_h.update(chunk)
                    sha512_h.update(chunk)
                    if has_blake3:
                        blake3_h.update(chunk)
                    dst.write(chunk)
                    written += len(chunk)
                    if self.on_progress:
                        self.on_progress(written, total_size)

            self.result.file_size = written
            self.result.sha256_inline = sha256_h.hexdigest()
            self.result.sha512_inline = sha512_h.hexdigest()
            if has_blake3:
                self.result.blake3_inline = blake3_h.hexdigest()

            self.result.status = "verifying"
            self.result.sha256_post = HashingEngine.compute_file_hash(
                self.dest, "sha256", callback=lambda r, t: None
            )
            self.result.hashes_match = (self.result.sha256_inline == self.result.sha256_post)
            self.result.end_time = datetime.datetime.utcnow().isoformat()

            start = datetime.datetime.fromisoformat(self.result.start_time)
            end = datetime.datetime.fromisoformat(self.result.end_time)
            self.result.duration_seconds = (end - start).total_seconds()
            self.result.status = "completed" if self.result.hashes_match else "hash_mismatch"

        except Exception as e:
            self.result.status = f"error: {str(e)}"
            self.result.end_time = datetime.datetime.utcnow().isoformat()

        if self.on_complete:
            self.on_complete(self.result)


class FAHTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Image Acquisition & Hashing Toolkit (FAHT-GUI)")
        self.root.geometry("1100x780")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self.case = CaseMetadata()
        self.engine = None
        self.results = []
        self.acquisition_thread = None

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

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Tab 1: Case Setup
        case_frame = ttk.Frame(notebook)
        notebook.add(case_frame, text=" Case Setup ")
        self._build_case_tab(case_frame)

        # Tab 2: Acquisition
        acq_frame = ttk.Frame(notebook)
        notebook.add(acq_frame, text=" Acquisition ")
        self._build_acquisition_tab(acq_frame)

        # Tab 3: Results & Hashing
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text=" Results & Verification ")
        self._build_results_tab(results_frame)

        # Tab 4: Report
        report_frame = ttk.Frame(notebook)
        notebook.add(report_frame, text=" Report ")
        self._build_report_tab(report_frame)

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

    def _build_case_tab(self, parent):
        ttk.Label(parent, text="Case Metadata", style="Title.TLabel").pack(pady=(10, 5))
        form = ttk.Frame(parent)
        form.pack(padx=20, pady=10, fill=tk.X)

        fields = [
            ("Case Number:", "case_number"),
            ("Evidence ID:", "evidence_id"),
            ("Examiner Name:", "examiner_name"),
            ("Organization:", "organization"),
        ]
        self.case_entries = {}
        for i, (label, key) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=i, column=0, sticky=tk.W, pady=3)
            e = ttk.Entry(form, width=50)
            e.grid(row=i, column=1, pady=3, padx=(10, 0))
            self.case_entries[key] = e

        ttk.Label(form, text="Notes:").grid(row=len(fields), column=0, sticky=tk.NW, pady=3)
        self.notes_text = tk.Text(form, width=50, height=4, bg=SURFACE2, fg=TEXT, insertbackground=PRIMARY, font=("Segoe UI", 10), borderwidth=0)
        self.notes_text.grid(row=len(fields), column=1, pady=3, padx=(10, 0))

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Save Case Metadata", style="Primary.TButton", command=self._save_case).pack()

    def _build_acquisition_tab(self, parent):
        ttk.Label(parent, text="Disk Image Acquisition", style="Title.TLabel").pack(pady=(10, 5))

        file_frame = ttk.LabelFrame(parent, text="File Selection")
        file_frame.pack(padx=15, pady=5, fill=tk.X)

        ttk.Label(file_frame, text="Source (Image/Device):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=3)
        self.source_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.source_var, width=60).grid(row=0, column=1, padx=5, pady=3)
        ttk.Button(file_frame, text="Browse", command=self._browse_source).grid(row=0, column=2, padx=5)

        ttk.Label(file_frame, text="Destination Path:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=3)
        self.dest_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.dest_var, width=60).grid(row=1, column=1, padx=5, pady=3)
        ttk.Button(file_frame, text="Browse", command=self._browse_dest).grid(row=1, column=2, padx=5)

        opt_frame = ttk.LabelFrame(parent, text="Options")
        opt_frame.pack(padx=15, pady=5, fill=tk.X)

        ttk.Label(opt_frame, text="Block Size:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.blocksize_var = tk.StringVar(value="65536")
        ttk.Combobox(opt_frame, textvariable=self.blocksize_var, values=["4096","8192","32768","65538","131072","524288","1048576"], width=12).grid(row=0, column=1, padx=5)

        ttk.Label(opt_frame, text="Output Format:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.format_var = tk.StringVar(value="RAW (.raw)")
        ttk.Combobox(opt_frame, textvariable=self.format_var, values=["RAW (.raw)","RAW (.dd)","RAW (.img)"], width=15).grid(row=0, column=3, padx=5)

        self.write_blocker_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Verify Write-Blocker (read-only)", variable=self.write_blocker_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=3)

        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(pady=10)
        self.start_btn = ttk.Button(ctrl_frame, text="Start Acquisition", style="Primary.TButton", command=self._start_acquisition)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_btn = ttk.Button(ctrl_frame, text="Cancel", style="Danger.TButton", command=self._cancel_acquisition, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        ttk.Label(parent, text="Progress:", style="Subtitle.TLabel").pack(anchor=tk.W, padx=15)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100, style="Horizontal.TProgressbar")
        self.progress_bar.pack(padx=15, fill=tk.X)

        self.progress_label_var = tk.StringVar(value="0 / 0 bytes")
        ttk.Label(parent, textvariable=self.progress_label_var, style="CardDim.TLabel").pack(anchor=tk.W, padx=15)

    def _build_results_tab(self, parent):
        ttk.Label(parent, text="Acquisition Results & Hash Verification", style="Title.TLabel").pack(pady=(10, 5))

        self.results_tree = ttk.Treeview(parent, columns=("status","source","size","sha256_inline","sha256_post","match"), show="headings", height=8)
        for col, w in [("status",80),("source",250),("size",100),("sha256_inline",120),("sha256_post",120),("match",60)]:
            self.results_tree.heading(col, text=col.replace("_"," ").title())
            self.results_tree.column(col, width=w)
        self.results_tree.pack(padx=15, fill=tk.BOTH, expand=True, pady=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Re-verify Selected", command=self._reverify).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export Hash Manifest", command=self._export_manifest).pack(side=tk.LEFT, padx=5)

        ttk.Label(parent, text="Detailed Hash Output:", style="Subtitle.TLabel").pack(anchor=tk.W, padx=15, pady=(5,0))
        self.hash_detail = scrolledtext.ScrolledText(parent, height=8, state=tk.DISABLED, bg=SURFACE, fg=TEXT, insertbackground=PRIMARY, font=("Consolas", 9), borderwidth=0)
        self.hash_detail.pack(padx=15, fill=tk.X)

    def _build_report_tab(self, parent):
        ttk.Label(parent, text="Forensic Report Generation", style="Title.TLabel").pack(pady=(10, 5))

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Generate JSON Report", style="Primary.TButton", command=lambda: self._export_report("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate CSV Report", command=lambda: self._export_report("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate Text Report", command=lambda: self._export_report("txt")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate HTML Report", command=lambda: self._export_report("html")).pack(side=tk.LEFT, padx=5)

        ttk.Label(parent, text="Report Preview:", style="Subtitle.TLabel").pack(anchor=tk.W, padx=15, pady=(5,0))
        self.report_preview = scrolledtext.ScrolledText(parent, height=25, bg=SURFACE, fg=TEXT, insertbackground=PRIMARY, font=("Consolas", 9), borderwidth=0)
        self.report_preview.pack(padx=15, fill=tk.BOTH, expand=True)

    def _save_case(self):
        for key, entry in self.case_entries.items():
            setattr(self.case, key, entry.get().strip())
        self.case.notes = self.notes_text.get("1.0", tk.END).strip()
        self.status_var.set("Case metadata saved.")
        messagebox.showinfo("Saved", "Case metadata saved successfully.")

    def _browse_source(self):
        path = filedialog.askopenfilename(title="Select Source Image/Device")
        if path:
            self.source_var.set(path)
            base = os.path.splitext(path)[0]
            ext = self.format_var.get().split("(")[-1].rstrip(")")
            self.dest_var.set(base + "_acquired" + ext)

    def _browse_dest(self):
        path = filedialog.asksaveasfilename(title="Select Destination Path")
        if path:
            self.dest_var.set(path)

    def _start_acquisition(self):
        source = self.source_var.get().strip()
        dest = self.dest_var.get().strip()
        if not source or not dest:
            messagebox.showerror("Error", "Please select source and destination paths.")
            return
        if not os.path.exists(source):
            messagebox.showerror("Error", f"Source file not found: {source}")
            return

        self._save_case()
        self.start_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.status_var.set("Acquiring...")
        self.progress_var.set(0)

        try:
            bs = int(self.blocksize_var.get())
        except ValueError:
            bs = 65536

        self.engine = AcquisitionEngine(source, dest, block_size=bs,
                                         on_progress=self._on_progress,
                                         on_complete=self._on_complete)
        self.acquisition_thread = threading.Thread(target=self.engine.run, daemon=True)
        self.acquisition_thread.start()

    def _cancel_acquisition(self):
        if self.engine:
            self.engine.cancel()
            self.status_var.set("Cancelling...")

    def _on_progress(self, done, total):
        if total:
            pct = (done / total) * 100
            self.progress_var.set(pct)
            self.progress_label_var.set(f"{done:,} / {total:,} bytes ({pct:.1f}%)")
        else:
            self.progress_label_var.set(f"{done:,} bytes processed")

    def _on_complete(self, result):
        self.root.after(0, lambda: self._handle_complete(result))

    def _handle_complete(self, result):
        self.results.append(result)
        status_text = result.status
        match_text = "YES" if result.hashes_match else "NO"

        self.results_tree.insert("", tk.END, values=(
            status_text,
            os.path.basename(result.source_path),
            f"{result.file_size:,}",
            result.sha256_inline[:16] + "...",
            result.sha256_post[:16] + "..." if result.sha256_post else "",
            match_text,
        ))

        self.hash_detail.config(state=tk.NORMAL)
        self.hash_detail.delete("1.0", tk.END)
        detail = (
            f"=== Acquisition Result ===\n"
            f"Source: {result.source_path}\n"
            f"Destination: {result.output_path}\n"
            f"Size: {result.file_size:,} bytes\n"
            f"Status: {result.status}\n\n"
            f"--- Inline Hashes ---\n"
            f"SHA-256:  {result.sha256_inline}\n"
            f"SHA-512:  {result.sha512_inline}\n"
            f"BLAKE3:   {result.blake3_inline or 'N/A (install blake3)'}\n\n"
            f"--- Post-Acquisition Hash ---\n"
            f"SHA-256:  {result.sha256_post}\n\n"
            f"Hashes Match: {'YES' if result.hashes_match else 'NO - TAMPER DETECTED'}\n"
            f"Duration: {result.duration_seconds:.1f}s\n"
        )
        self.hash_detail.insert(tk.END, detail)
        self.hash_detail.config(state=tk.DISABLED)

        self.start_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.status_var.set(f"Acquisition {result.status}.")
        if not result.hashes_match:
            messagebox.showwarning("Hash Mismatch", "WARNING: Inline and post-acquisition hashes do NOT match! Image may be corrupted or tampered.")

    def _reverify(self):
        sel = self.results_tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a result row first.")
            return
        idx = self.results_tree.index(sel[0])
        result = self.results[idx]
        self.status_var.set(f"Re-verifying {os.path.basename(result.output_path)}...")

        def do_verify():
            new_hash = HashingEngine.compute_file_hash(result.output_path, "sha256")
            result.sha256_post = new_hash
            result.hashes_match = (result.sha256_inline == new_hash)
            self.root.after(0, lambda: self._on_complete(result))

        threading.Thread(target=do_verify, daemon=True).start()

    def _export_manifest(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source","Destination","Size","SHA256_Inline","SHA256_Post","Match","Status","Start","End","Duration"])
            for r in self.results:
                writer.writerow([r.source_path,r.output_path,r.file_size,r.sha256_inline,r.sha256_post,r.hashes_match,r.status,r.start_time,r.end_time,r.duration_seconds])
        self.status_var.set(f"Manifest exported to {path}")

    def _export_report(self, fmt):
        if not self.results:
            messagebox.showinfo("Info", "No results to report.")
            return

        report_data = {
            "report_title": "Forensic Image Acquisition Report",
            "generated_utc": datetime.datetime.utcnow().isoformat(),
            "case_metadata": asdict(self.case),
            "acquisitions": [asdict(r) for r in self.results],
        }

        if fmt == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
            if path:
                with open(path, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
                self._show_report_preview(json.dumps(report_data, indent=2, default=str))
                self.status_var.set(f"JSON report exported to {path}")

        elif fmt == "csv":
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
            if path:
                with open(path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Field","Value"])
                    writer.writerow(["Case Number", self.case.case_number])
                    writer.writerow(["Evidence ID", self.case.evidence_id])
                    writer.writerow(["Examiner", self.case.examiner_name])
                    writer.writerow(["Generated", report_data["generated_utc"]])
                    writer.writerow([])
                    writer.writerow(["Source","Destination","Size","SHA256","Match","Status","Duration"])
                    for r in self.results:
                        writer.writerow([r.source_path,r.output_path,r.file_size,r.sha256_inline,r.hashes_match,r.status,f"{r.duration_seconds:.1f}s"])
                self.status_var.set(f"CSV report exported to {path}")

        elif fmt == "txt":
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
            if path:
                lines = [
                    "FORENSIC IMAGE ACQUISITION REPORT",
                    "=" * 50,
                    f"Generated: {report_data['generated_utc']}",
                    f"Case Number: {self.case.case_number}",
                    f"Evidence ID: {self.case.evidence_id}",
                    f"Examiner: {self.case.examiner_name}",
                    f"Organization: {self.case.organization}",
                    f"Notes: {self.case.notes}",
                    "",
                    "ACQUISITION RESULTS",
                    "-" * 50,
                ]
                for i, r in enumerate(self.results, 1):
                    lines.extend([
                        f"\nAcquisition #{i}",
                        f"  Source: {r.source_path}",
                        f"  Destination: {r.output_path}",
                        f"  Size: {r.file_size:,} bytes",
                        f"  Status: {r.status}",
                        f"  SHA-256 (inline): {r.sha256_inline}",
                        f"  SHA-256 (post):   {r.sha256_post}",
                        f"  Hashes Match: {'YES' if r.hashes_match else 'NO'}",
                        f"  Duration: {r.duration_seconds:.1f}s",
                    ])
                with open(path, "w") as f:
                    f.write("\n".join(lines))
                self._show_report_preview("\n".join(lines))
                self.status_var.set(f"Text report exported to {path}")

        elif fmt == "html":
            path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
            if path:
                html = self._generate_html_report()
                with open(path, "w") as f:
                    f.write(html)
                self._show_report_preview(html[:3000])
                self.status_var.set(f"HTML report exported to {path}")

    def _generate_html_report(self):
        rows = ""
        for i, r in enumerate(self.results, 1):
            color = "green" if r.hashes_match else "red"
            match = "YES" if r.hashes_match else "NO"
            rows += f"""
            <tr>
                <td>{i}</td>
                <td>{os.path.basename(r.source_path)}</td>
                <td>{r.file_size:,}</td>
                <td style="font-family:monospace;font-size:10px">{r.sha256_inline}</td>
                <td style="font-family:monospace;font-size:10px">{r.sha256_post}</td>
                <td style="color:{color};font-weight:bold">{match}</td>
                <td>{r.status}</td>
                <td>{r.duration_seconds:.1f}s</td>
            </tr>"""
        return f"""<!DOCTYPE html>
<html><head><title>FAHT Report - {self.case.case_number}</title>
<style>
body {{ font-family: Arial; margin: 20px; background: #0d1117; color: #e6edf3; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
th, td {{ border: 1px solid #30363d; padding: 6px 8px; text-align: left; }}
th {{ background: #161b22; color: #58a6ff; }}
.header {{ background: #161b22; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
</style></head><body>
<h1>Forensic Image Acquisition Report</h1>
<div class="header">
    <p><strong>Case Number:</strong> {self.case.case_number} | <strong>Evidence ID:</strong> {self.case.evidence_id}</p>
    <p><strong>Examiner:</strong> {self.case.examiner_name} | <strong>Organization:</strong> {self.case.organization}</p>
    <p><strong>Generated:</strong> {datetime.datetime.utcnow().isoformat()}</p>
    <p><strong>Notes:</strong> {self.case.notes}</p>
</div>
<h2>Acquisition Results</h2>
<table>
<tr><th>#</th><th>Source</th><th>Size</th><th>SHA-256 (Inline)</th><th>SHA-256 (Post)</th><th>Match</th><th>Status</th><th>Duration</th></tr>
{rows}
</table>
<h2>Host Telemetry</h2>
<pre>{json.dumps(self.results[0].host_info if self.results else {}, indent=2)}</pre>
</body></html>"""

    def _show_report_preview(self, text):
        self.report_preview.config(state=tk.NORMAL)
        self.report_preview.delete("1.0", tk.END)
        self.report_preview.insert(tk.END, text)
        self.report_preview.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    app = FAHTApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
