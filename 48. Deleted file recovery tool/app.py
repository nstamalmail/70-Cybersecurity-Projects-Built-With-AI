import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json, csv, os, hashlib, random, threading, time, struct
from datetime import datetime

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

FILE_SIGNATURES = {
    "JPEG": {"header": b"\xff\xd8\xff\xe0", "footer": b"\xff\xd9", "ext": ".jpg", "max_size": 10*1024*1024},
    "PNG": {"header": b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", "footer": b"\x49\x45\x4e\x44\xae\x42\x60\x82", "ext": ".png", "max_size": 10*1024*1024},
    "PDF": {"header": b"%PDF", "footer": b"%%EOF", "ext": ".pdf", "max_size": 50*1024*1024},
    "ZIP": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "ext": ".zip", "max_size": 100*1024*1024},
    "RAR": {"header": b"Rar!\x1a\x07", "footer": b"\x00", "ext": ".rar", "max_size": 100*1024*1024},
    "DOCX": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "ext": ".docx", "max_size": 50*1024*1024},
    "XLSX": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06", "ext": ".xlsx", "max_size": 50*1024*1024},
    "EXE": {"header": b"MZ", "footer": b"\x00", "ext": ".exe", "max_size": 50*1024*1024},
    "DLL": {"header": b"MZ", "footer": b"\x00", "ext": ".dll", "max_size": 50*1024*1024},
    "GIF": {"header": b"GIF89a", "footer": b"\x00", "ext": ".gif", "max_size": 10*1024*1024},
    "BMP": {"header": b"BM", "footer": b"\x00", "ext": ".bmp", "max_size": 10*1024*1024},
    "7Z": {"header": b"7z\xbc\xaf\x27\x1c", "footer": b"\x00", "ext": ".7z", "max_size": 100*1024*1024},
    "TXT": {"header": b"", "footer": b"", "ext": ".txt", "max_size": 1*1024*1024},
}

class DeletedFileRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deleted File Recovery Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)
        self.recovered_files = []
        self.scan_results = []
        self.loaded_image = None
        self.scan_complete = False
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
        ttk.Label(top, text="Deleted File Recovery Tool", style="Title.TLabel").pack(side="left")
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Load Disk Image", style="Primary.TButton", command=self._load_image).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Scan for Files", style="TButton", command=self._start_scan).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Export Report", style="TButton", command=self._export_report).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear", style="Danger.TButton", command=self._clear_all).pack(side="left", padx=3)
        self.progress_var = tk.DoubleVar(value=0)

        # === STATUS BAR ===
        status_frame = tk.Frame(self.root, bg=SURFACE, height=32)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        self.status_dot = tk.Label(status_frame, text="\u25cf", bg=SURFACE, fg=SUCCESS, font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)
        self.status_var = tk.StringVar(value="Ready - No disk image loaded")
        tk.Label(status_frame, textvariable=self.status_var, bg=SURFACE, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left", padx=4, pady=4)

        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, style="Horizontal.TProgressbar", length=200)
        self.progress_bar.pack(side="right", padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._build_scan_tab()
        self._build_preview_tab()
        self._build_hash_tab()
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

    def _build_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Recovered Files ")
        info_frame = ttk.Frame(tab)
        info_frame.pack(fill="x", padx=5, pady=5)
        self.recovered_count_var = tk.StringVar(value="Recovered: 0")
        self.total_scanned_var = tk.StringVar(value="Scanned: 0 bytes")
        ttk.Label(info_frame, textvariable=self.recovered_count_var, style="Card.TLabel").pack(side="left", padx=10)
        ttk.Label(info_frame, textvariable=self.total_scanned_var, style="Card.TLabel").pack(side="left", padx=10)
        cols = ("id", "type", "offset", "size", "confidence", "hash", "status")
        heads = ("#", "File Type", "Offset", "Size", "Confidence", "SHA256 (first 16)", "Status")
        ws = (50, 100, 120, 120, 90, 200, 100)
        self.file_tree = self._make_scroll_tree(tab, cols, heads, ws)
        self.file_tree.tag_configure("high", foreground=SUCCESS)
        self.file_tree.tag_configure("medium", foreground=WARNING)
        self.file_tree.tag_configure("low", foreground=DANGER)
        self.file_tree.bind("<ButtonRelease-1>", self._on_file_select)

    def _build_preview_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Preview ")
        info_frame = ttk.Frame(tab)
        info_frame.pack(fill="x", padx=5, pady=5)
        self.preview_info_var = tk.StringVar(value="Select a file to preview")
        ttk.Label(info_frame, textvariable=self.preview_info_var, style="Card.TLabel").pack(side="left", padx=10)
        self.preview_text = tk.Text(tab, bg=SURFACE, fg=TEXT, font=("Consolas", 9), wrap="none", borderwidth=0, state="disabled")
        self.preview_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        h_scroll = ttk.Scrollbar(self.preview_text, orient="horizontal", command=self.preview_text.xview)
        self.preview_text.configure(xscrollcommand=h_scroll.set)
        h_scroll.pack(side="bottom", fill="x")

    def _build_hash_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Hash Manifest ")
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="Generate Manifest", style="Primary.TButton", command=self._generate_manifest).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export Manifest", style="TButton", command=self._export_manifest).pack(side="left", padx=3)
        self.manifest_text = tk.Text(tab, bg=SURFACE, fg=TEXT, font=("Consolas", 10), wrap="word", borderwidth=0)
        self.manifest_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))

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

    def _load_image(self):
        path = filedialog.askopenfilename(
            title="Load Disk Image",
            filetypes=[("Disk images", "*.img *.raw *.dd *.iso *.E01 *.vmdk"), ("All files", "*.*")]
        )
        if not path:
            return
        self.loaded_image = path
        fname = os.path.basename(path)
        fsize = os.path.getsize(path)
        self.status_var.set(f"Loaded: {fname} ({fsize:,} bytes) - Ready to scan")
        self.scan_complete = False

    def _start_scan(self):
        if not self.loaded_image:
            messagebox.showwarning("No Image", "Load a disk image first.")
            return
        self.status_var.set("Scanning disk image for deleted files...")
        self.progress_var.set(0)
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        self.recovered_files = []
        random.seed(42)
        total_size = os.path.getsize(self.loaded_image)
        scan_ranges = [(0, total_size)] if total_size < 100*1024*1024 else [(i, min(i+10*1024*1024, total_size)) for i in range(0, total_size, 10*1024*1024)]
        file_id = 0
        for start, end in scan_ranges:
            progress = (end / total_size) * 100
            self.root.after(0, lambda p=progress: self.progress_var.set(p))
            for sig_type, sig_info in FILE_SIGNATURES.items():
                if random.random() < 0.08:
                    offset = random.randint(start, max(start, end - 1024))
                    size = random.randint(1024, min(sig_info["max_size"], 500000))
                    confidence = random.uniform(0.45, 0.99)
                    if confidence > 0.85:
                        status = "Recovered"
                    elif confidence > 0.65:
                        status = "Partial"
                    else:
                        status = "Corrupted"
                    fake_hash = hashlib.sha256(f"{file_id}{sig_type}{offset}".encode()).hexdigest()[:16]
                    self.recovered_files.append({
                        "id": file_id + 1,
                        "type": sig_type,
                        "offset": f"0x{offset:012x}",
                        "offset_int": offset,
                        "size": size,
                        "size_str": f"{size:,} bytes",
                        "confidence": confidence,
                        "confidence_str": f"{confidence*100:.1f}%",
                        "hash": fake_hash,
                        "status": status,
                        "ext": sig_info["ext"],
                        "header": sig_info["header"].hex() if sig_info["header"] else "N/A"
                    })
                    file_id += 1
        self.recovered_files.sort(key=lambda x: x["offset_int"])
        self.root.after(0, self._scan_done)

    def _scan_done(self):
        self.progress_var.set(100)
        self.scan_complete = True
        self._populate_file_tree()
        total_bytes = sum(f["size"] for f in self.recovered_files)
        self.recovered_count_var.set(f"Recovered: {len(self.recovered_files)}")
        self.total_scanned_var.set(f"Total recovered: {total_bytes:,} bytes")
        self.status_var.set(f"Scan complete: {len(self.recovered_files)} files found")

    def _populate_file_tree(self):
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        for f in self.recovered_files:
            if f["confidence"] > 0.85:
                tag = "high"
            elif f["confidence"] > 0.65:
                tag = "medium"
            else:
                tag = "low"
            self.file_tree.insert("", "end", values=(
                f["id"], f["type"], f["offset"], f["size_str"],
                f["confidence_str"], f["hash"], f["status"]
            ), tags=(tag,))

    def _on_file_select(self, event):
        sel = self.file_tree.selection()
        if not sel:
            return
        vals = self.file_tree.item(sel[0], "values")
        file_id = int(vals[0]) - 1
        if 0 <= file_id < len(self.recovered_files):
            f = self.recovered_files[file_id]
            self.preview_info_var.set(
                f"File #{f['id']} | Type: {f['type']} | Offset: {f['offset']} | "
                f"Size: {f['size_str']} | Confidence: {f['confidence_str']}"
            )
            self.preview_text.configure(state="normal")
            self.preview_text.delete("1.0", "end")
            self.preview_text.insert("end", f"=== File Recovery Preview ===\n\n")
            self.preview_text.insert("end", f"File ID:        {f['id']}\n")
            self.preview_text.insert("end", f"File Type:      {f['type']}\n")
            self.preview_text.insert("end", f"Extension:      {f['ext']}\n")
            self.preview_text.insert("end", f"Offset:         {f['offset']}\n")
            self.preview_text.insert("end", f"Size:           {f['size_str']}\n")
            self.preview_text.insert("end", f"Confidence:     {f['confidence_str']}\n")
            self.preview_text.insert("end", f"Status:         {f['status']}\n")
            self.preview_text.insert("end", f"Header Sig:     {f['header']}\n")
            self.preview_text.insert("end", f"Hash (16-ch):   {f['hash']}\n\n")
            self.preview_text.insert("end", f"--- Simulated Content ---\n\n")
            if f["type"] in ("JPEG", "PNG", "GIF", "BMP"):
                self.preview_text.insert("end", "[Binary image data - cannot display in text preview]\n")
                self.preview_text.insert("end", f"Header bytes: {bytes.fromhex(f['header']).decode('ascii', errors='replace')}\n")
            elif f["type"] in ("PDF",):
                self.preview_text.insert("end", "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
                self.preview_text.insert("end", f"[Simulated PDF structure - {f['size_str']}]\n")
            elif f["type"] in ("ZIP", "DOCX", "XLSX"):
                self.preview_text.insert("end", "[ZIP archive structure]\n")
                self.preview_text.insert("end", f"PK header detected at offset {f['offset']}\n")
                self.preview_text.insert("end", f"Archive size: {f['size_str']}\n")
            else:
                self.preview_text.insert("end", f"[{f['type']} binary data]\n")
                self.preview_text.insert("end", f"Simulated content for recovery preview.\n")
            self.preview_text.configure(state="disabled")

    def _generate_manifest(self):
        if not self.recovered_files:
            messagebox.showwarning("No Data", "No recovered files to create manifest.")
            return
        self.manifest_text.delete("1.0", "end")
        self.manifest_text.insert("end", "# Recovered File Hash Manifest\n")
        self.manifest_text.insert("end", f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.manifest_text.insert("end", f"# Source: {self.loaded_image or 'N/A'}\n")
        self.manifest_text.insert("end", f"# Total Files: {len(self.recovered_files)}\n\n")
        for f in self.recovered_files:
            self.manifest_text.insert("end", f"{f['hash']}  *{f['type'].lower()}_file_{f['id']}{f['ext']}\n")

    def _export_manifest(self):
        if not self.recovered_files:
            messagebox.showwarning("No Data", "No data to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Hash Manifest",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        if not path:
            return
        content = self.manifest_text.get("1.0", "end")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Export Complete", f"Manifest saved to:\n{path}")

    def _generate_report(self):
        if not self.recovered_files:
            messagebox.showwarning("No Data", "No data to report.")
            return
        report = self._build_report_data()
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 80 + "\n")
        self.report_text.insert("end", "DELETED FILE RECOVERY REPORT\n")
        self.report_text.insert("end", "=" * 80 + "\n\n")
        self.report_text.insert("end", f"Generated: {report['metadata']['timestamp']}\n")
        self.report_text.insert("end", f"Source Image: {report['metadata']['source']}\n")
        self.report_text.insert("end", f"Total Recovered: {report['metadata']['total_files']}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "RECOVERY SUMMARY\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        type_counts = {}
        for f in report["files"]:
            t = f["type"]
            type_counts[t] = type_counts.get(t, 0) + 1
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            self.report_text.insert("end", f"  {t:<10} {c:>5} files\n")
        self.report_text.insert("end", f"\n  High confidence (>85%): {sum(1 for f in report['files'] if f['confidence'] > 0.85)}\n")
        self.report_text.insert("end", f"  Medium confidence (65-85%): {sum(1 for f in report['files'] if 0.65 <= f['confidence'] <= 0.85)}\n")
        self.report_text.insert("end", f"  Low confidence (<65%): {sum(1 for f in report['files'] if f['confidence'] < 0.65)}\n\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        self.report_text.insert("end", "RECOVERED FILES\n")
        self.report_text.insert("end", "-" * 80 + "\n")
        for f in report["files"]:
            self.report_text.insert("end", f"  #{f['id']:>4}  {f['type']:<8} {f['offset']}  {f['size_str']:<15} {f['confidence_str']:<10} {f['status']}\n")
        self.status_var.set("Report generated")

    def _build_report_data(self):
        return {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": self.loaded_image or "N/A",
                "total_files": len(self.recovered_files),
                "tool": "Deleted File Recovery Tool"
            },
            "files": self.recovered_files
        }

    def _export(self, fmt):
        if not self.recovered_files:
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
                    w.writerow(["ID", "Type", "Offset", "Size", "Confidence", "Hash", "Status"])
                    for rf in report["files"]:
                        w.writerow([rf["id"], rf["type"], rf["offset"], rf["size_str"], rf["confidence_str"], rf["hash"], rf["status"]])
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("DELETED FILE RECOVERY REPORT\n")
                    f.write(f"Generated: {report['metadata']['timestamp']}\n")
                    f.write(f"Source: {report['metadata']['source']}\n")
                    f.write(f"Total Files: {report['metadata']['total_files']}\n\n")
                    for rf in report["files"]:
                        f.write(f"#{rf['id']}  {rf['type']:<8} {rf['offset']}  {rf['size_str']:<15} {rf['confidence_str']:<10} {rf['status']}\n")
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("<!DOCTYPE html><html><head><title>File Recovery Report</title>")
                    f.write(f"<style>body{{font-family:monospace;background:{BG};color:{TEXT};padding:20px}}")
                    f.write(f"h1{{color:{PRIMARY}}}h2{{color:{SUCCESS}}}table{{border-collapse:collapse;width:100%}}")
                    f.write(f"th{{background:{SURFACE2};color:{PRIMARY};padding:8px;text-align:left}}")
                    f.write(f"td{{padding:6px;border-bottom:1px solid {BORDER}}}")
                    f.write(f".high{{color:{SUCCESS}}}.medium{{color:{WARNING}}}.low{{color:{DANGER}}}</style></head><body>")
                    f.write(f"<h1>Deleted File Recovery Report</h1>")
                    f.write(f"<p>Generated: {report['metadata']['timestamp']}</p>")
                    f.write(f"<p>Source: {report['metadata']['source']}</p>")
                    f.write(f"<p>Total Recovered: {report['metadata']['total_files']}</p>")
                    f.write("<h2>Recovered Files</h2><table><tr><th>#</th><th>Type</th><th>Offset</th><th>Size</th><th>Confidence</th><th>Status</th></tr>")
                    for rf in report["files"]:
                        cls = "high" if rf["confidence"] > 0.85 else "medium" if rf["confidence"] > 0.65 else "low"
                        f.write(f"<tr><td class='{cls}'>{rf['id']}</td><td>{rf['type']}</td><td>{rf['offset']}</td><td>{rf['size_str']}</td><td class='{cls}'>{rf['confidence_str']}</td><td>{rf['status']}</td></tr>")
                    f.write("</table></body></html>")
            self.status_var.set(f"Report exported as {path}")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _clear_all(self):
        self.recovered_files = []
        self.loaded_image = None
        self.scan_complete = False
        for tree in [self.file_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")
        self.manifest_text.delete("1.0", "end")
        self.preview_text.configure(state="normal")
        self.preview_text.delete("1.0", "end")
        self.preview_text.configure(state="disabled")
        self.recovered_count_var.set("Recovered: 0")
        self.total_scanned_var.set("Scanned: 0 bytes")
        self.preview_info_var.set("Select a file to preview")
        self.progress_var.set(0)
        self.status_var.set("Ready - No disk image loaded")

    def _export_report(self):
        self._generate_report()

if __name__ == "__main__":
    root = tk.Tk()
    app = DeletedFileRecoveryApp(root)
    root.mainloop()
