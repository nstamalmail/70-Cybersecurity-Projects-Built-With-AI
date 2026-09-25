"""RECT GUI tabs: Workspace, Analysis, Crypto, Ops log, Writeup, Console."""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app import __version__
from app.config import APP_NAME, SAMPLES_DIR, get_data_dir, get_reports_dir
from app.gui.widgets import (ACCENT, FONT_FAMILY, add_text, log_to_text,
                             make_tree)


class WorkspaceTab(ttk.Frame):
    """Challenge case metadata + binary loading."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(1, weight=1)
        self.on_load_binary = None
        self.on_import_sample = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        ttk.Label(self, text="Challenge name:").grid(row=0, column=0, sticky="w", **pad)
        self.name_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.name_var).grid(row=0, column=1, sticky="ew", **pad)

        ttk.Label(self, text="Category:").grid(row=1, column=0, sticky="w", **pad)
        self.category_var = tk.StringVar(value="rev")
        ttk.Combobox(self, textvariable=self.category_var, state="readonly",
                     values=["rev", "crypto", "pwn", "misc", "forensics"],
                     width=14).grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(self, text="Event:").grid(row=2, column=0, sticky="w", **pad)
        self.event_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.event_var).grid(row=2, column=1, sticky="ew", **pad)

        ttk.Label(self, text="Flag format:").grid(row=3, column=0, sticky="w", **pad)
        fmtrow = ttk.Frame(self, style="TFrame")
        fmtrow.grid(row=3, column=1, sticky="w", **pad)
        self.flag_format_var = tk.StringVar(value="flag{")
        ttk.Entry(fmtrow, textvariable=self.flag_format_var, width=16).pack(side="left")
        ttk.Label(fmtrow, text="  (prefix used to auto-spot flags in outputs)",
                  foreground="#7f849c").pack(side="left")

        ttk.Label(self, text="Description:").grid(row=4, column=0, sticky="nw", **pad)
        wrap_d = ttk.Frame(self, style="TFrame")
        wrap_d.grid(row=4, column=1, sticky="ew", **pad)
        self.desc_text = add_text(wrap_d, height=4)

        ttk.Label(self, text="Binary / file:").grid(row=5, column=0, sticky="w", **pad)
        brow = ttk.Frame(self, style="TFrame")
        brow.grid(row=5, column=1, sticky="ew", **pad)
        self.binary_var = tk.StringVar()
        ttk.Entry(brow, textvariable=self.binary_var).pack(side="left", fill="x",
                                                           expand=True)
        ttk.Button(brow, text="📂 Browse…", command=self._browse).pack(side="left", padx=6)
        ttk.Button(brow, text="⬆ Load sample challenge file…", style="Accent.TButton",
                   command=self._load_sample).pack(side="left")

        ttk.Button(self, text="📦 Load binary & analyze",
                   command=self._load).grid(row=6, column=1, sticky="w", **pad)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select challenge file")
        if path:
            self.binary_var.set(path)

    def _load_sample(self):
        path = filedialog.askopenfilename(
            title="Load sample challenge file", initialdir=SAMPLES_DIR,
            filetypes=[("All files", "*.*")])
        if path and self.on_import_sample:
            self.on_import_sample(path)

    def _load(self):
        if self.on_load_binary:
            self.on_load_binary()

    def collect(self) -> dict:
        return {
            "challenge_name": self.name_var.get().strip(),
            "category": self.category_var.get(),
            "event": self.event_var.get().strip(),
            "description": self.desc_text.get("1.0", "end").strip(),
            "flag_format": self.flag_format_var.get().strip() or "flag{",
            "binary_path": self.binary_var.get().strip(),
        }

    def apply(self, data: dict):
        self.name_var.set(data.get("challenge_name", data.get("name", "")))
        self.category_var.set(data.get("category", "rev"))
        self.event_var.set(data.get("event", ""))
        self.desc_text.delete("1.0", "end")
        self.desc_text.insert("1.0", data.get("description", ""))
        self.flag_format_var.set(data.get("flag_format", "flag{"))
        self.binary_var.set(data.get("binary_path", ""))


class AnalysisTab(ttk.Frame):
    """Binary info, hex view, strings table, entropy map, disassembly."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        self.info_var = tk.StringVar(value="No binary loaded.")
        ttk.Label(self, textvariable=self.info_var, foreground=ACCENT).grid(
            row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        nb = ttk.Notebook(self)
        nb.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # strings
        strings_wrap = ttk.Frame(nb, style="TFrame")
        self.strings_tree = make_tree(
            strings_wrap, ("offset", "cls", "text"),
            ("Offset", "Class", "String"), (110, 130, 720))
        nb.add(strings_wrap, text=" Strings ")

        # hex view
        hex_wrap = ttk.Frame(nb, style="TFrame")
        self.hex_text = add_text(hex_wrap, height=20)
        nb.add(hex_wrap, text=" Hex ")

        # entropy
        ent_wrap = ttk.Frame(nb, style="TFrame")
        self.ent_text = add_text(ent_wrap, height=20)
        nb.add(ent_wrap, text=" Entropy ")

        # disasm (capstone optional)
        dis_wrap = ttk.Frame(nb, style="TFrame")
        self.disasm_text = add_text(dis_wrap, height=20)
        nb.add(dis_wrap, text=" Disassembly (optional capstone) ")

    def set_info(self, info):
        packed = ", PACKED" if info.packed else ""
        self.info_var.set(
            f"{os.path.basename(info.path)} — {info.file_type}, "
            f"{info.architecture or 'unknown arch'}, {info.bits or '?'}-bit, "
            f"entropy {info.entropy:.2f}{packed}, {len(info.strings)} strings")

    def set_info_text(self, text: str):
        self.info_var.set(text)

    def set_strings(self, strings: list):
        self.strings_tree.delete(*self.strings_tree.get_children())
        for s in strings[:3000]:
            self.strings_tree.insert("", "end", values=(
                f"0x{s['offset']:08x}", s.get("class", ""), s["text"][:200]))

    def set_hex(self, data: bytes, limit: int = 4096):
        data = data[:limit]
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08x}  {hexpart:<47}  {asc}")
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        self.hex_text.insert("1.0", "\n".join(lines))
        self.hex_text.configure(state="disabled")

    def set_entropy(self, entropy: float, blocks: list):
        lines = [f"Total entropy: {entropy:.3f} bits/byte", ""]
        for i, e in enumerate(blocks[:512]):
            bar = "█" * int(e * 4)
            lines.append(f"block {i:04d} (0x{i*256:06x}): {e:5.2f} {bar}")
        self.ent_text.configure(state="normal")
        self.ent_text.delete("1.0", "end")
        self.ent_text.insert("1.0", "\n".join(lines))
        self.ent_text.configure(state="disabled")

    def set_disasm(self, text: str):
        self.disasm_text.configure(state="normal")
        self.disasm_text.delete("1.0", "end")
        self.disasm_text.insert("1.0", text)
        self.disasm_text.configure(state="disabled")


class CryptoTab(ttk.Frame):
    """Encoding/decoding, XOR, hash ID, classical ciphers, RSA."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.on_run = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)

        row0 = ttk.LabelFrame(self, text=" Operation ", padding=8)
        row0.grid(row=0, column=0, sticky="ew", **pad)
        self.op_var = tk.StringVar(value="decode")
        ttk.Combobox(row0, textvariable=self.op_var, state="readonly",
                     values=["decode", "encode", "xor", "hashid", "caesar",
                             "vigenere", "rsa"],
                     width=10).pack(side="left")
        ttk.Label(row0, text="Encoding:").pack(side="left", padx=(14, 2))
        self.enc_var = tk.StringVar(value="auto")
        ttk.Combobox(row0, textvariable=self.enc_var, state="readonly",
                     values=["auto", "base64", "base32", "base16", "hex",
                             "url", "rot13", "reverse"], width=9).pack(side="left")
        ttk.Label(row0, text="Key:").pack(side="left", padx=(14, 2))
        self.key_var = tk.StringVar()
        ttk.Entry(row0, textvariable=self.key_var, width=18).pack(side="left")

        row1 = ttk.LabelFrame(self, text=" Input (text, or n=… e=… c=… p=… for RSA) ",
                              padding=8)
        row1.grid(row=1, column=0, sticky="ew", **pad)
        wrap_in = ttk.Frame(row1, style="TFrame")
        wrap_in.pack(fill="both", expand=True)
        self.input_text = add_text(wrap_in, height=4)
        ttk.Button(row1, text="▶ Run", style="Accent.TButton",
                   command=self._run).pack(anchor="e", pady=(6, 0))

        row2 = ttk.LabelFrame(self, text=" Output ", padding=8)
        row2.grid(row=2, column=0, sticky="nsew", **pad)
        wrap_out = ttk.Frame(row2, style="TFrame")
        wrap_out.pack(fill="both", expand=True)
        self.output_text = add_text(wrap_out, height=14)

    def _run(self):
        if self.on_run:
            self.on_run()

    def collect(self) -> dict:
        return {
            "op": self.op_var.get(),
            "encoding": self.enc_var.get(),
            "key": self.key_var.get(),
            "value": self.input_text.get("1.0", "end").strip(),
        }

    def set_output(self, text: str):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.configure(state="disabled")


class OpsTab(ttk.Frame):
    """Recorded operations (replayable command log) + console."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=2)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.ops_tree = make_tree(wrap, ("tool", "operation", "input", "output", "ok"),
                                  ("Tool", "Operation", "Input", "Output", "OK"),
                                  (90, 170, 220, 380, 46))

        con = ttk.LabelFrame(self, text=" Console ", padding=4)
        con.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.log_text = add_text(con, height=10)
        self.log_text.tag_configure("warn", foreground="#f9e2af")
        self.log_text.tag_configure("flag", foreground="#a6e3a1")

    def add_record(self, rec: dict):
        self.ops_tree.insert("", "end", values=(
            rec.get("tool", ""), rec.get("operation", ""),
            str(rec.get("input_summary", ""))[:60],
            str(rec.get("output_summary", ""))[:80],
            "✔" if rec.get("success") else "✖"))

    def log(self, line: str, tag: str = ""):
        log_to_text(self.log_text, line, tag)

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")


class WriteupTab(ttk.Frame):
    """Notes, flag capture, and writeup export."""

    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.on_export = None
        self.on_save_flag = None
        self._build()

    def _build(self):
        pad = dict(padx=10, pady=4)
        row0 = ttk.Frame(self, style="TFrame")
        row0.grid(row=0, column=0, sticky="ew", **pad)
        ttk.Label(row0, text="Recovered flag:").pack(side="left")
        self.flag_var = tk.StringVar()
        ttk.Entry(row0, textvariable=self.flag_var, width=52).pack(side="left", padx=6)
        self.solved_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row0, text="Solved", variable=self.solved_var).pack(side="left")
        ttk.Button(row0, text="💾 Save flag/status", command=self._save_flag).pack(
            side="left", padx=6)

        notesf = ttk.LabelFrame(self, text=" Notes (Markdown) ", padding=8)
        notesf.grid(row=1, column=0, sticky="nsew", **pad)
        wrap_n = ttk.Frame(notesf, style="TFrame")
        wrap_n.pack(fill="both", expand=True)
        self.notes_text = add_text(wrap_n, height=16)

        row1 = ttk.Frame(self, style="TFrame")
        row1.grid(row=2, column=0, sticky="ew", **pad)
        ttk.Button(row1, text="📖 Export writeup (Markdown/HTML/JSON/CSV)…",
                   style="Accent.TButton", command=self._export).pack(side="left")
        self.export_dir_var = tk.StringVar(value=get_reports_dir())
        ttk.Label(row1, text=" to ").pack(side="left")
        ttk.Entry(row1, textvariable=self.export_dir_var, width=40).pack(
            side="left", padx=4)
        ttk.Button(row1, text="📂", width=3,
                   command=self._pick_dir).pack(side="left")

    def _save_flag(self):
        if self.on_save_flag:
            self.on_save_flag()

    def _export(self):
        if self.on_export:
            self.on_export()

    def _pick_dir(self):
        d = filedialog.askdirectory(title="Choose writeup export folder")
        if d:
            self.export_dir_var.set(d)

    def collect(self) -> dict:
        return {
            "flag": self.flag_var.get().strip(),
            "solved": self.solved_var.get(),
            "notes_md": self.notes_text.get("1.0", "end").strip(),
        }

    def apply(self, data: dict):
        self.flag_var.set(data.get("flag", ""))
        self.solved_var.set(bool(data.get("solved", False)))
        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", data.get("notes_md", ""))


class HistoryTab(ttk.Frame):
    """Saved challenges from SQLite."""

    def __init__(self, master, db=None):
        super().__init__(master, style="TFrame")
        self.db = db
        self.on_load_challenge = None
        self.on_delete_challenge = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        self.tree = make_tree(wrap, ("id", "name", "category", "event",
                                     "solved", "flag"),
                              ("ID", "Name", "Category", "Event", "Solved", "Flag"),
                              (44, 220, 90, 160, 70, 320))

        btns = ttk.Frame(self, style="TFrame")
        btns.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btns, text="↻ Refresh", command=self.refresh).pack(side="left")
        ttk.Button(btns, text="📄 Open in workspace",
                   command=self._open).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Delete selected", style="Danger.TButton",
                   command=self._delete).pack(side="left", padx=6)

    def refresh(self):
        if not self.db:
            return
        self.tree.delete(*self.tree.get_children())
        for row in self.db.list_challenges():
            self.tree.insert("", "end", values=(
                row["id"], row["name"], row["category"], row["event"] or "",
                "✔" if row["solved"] else "—", row["flag"] or ""))

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a challenge first.")
            return None
        return int(self.tree.item(sel[0], "values")[0])

    def _open(self):
        cid = self._selected_id()
        if cid is not None and self.on_load_challenge:
            self.on_load_challenge(cid)

    def _delete(self):
        cid = self._selected_id()
        if cid is None:
            return
        if messagebox.askyesno(APP_NAME, f"Delete challenge #{cid}?"):
            if self.on_delete_challenge:
                self.on_delete_challenge(cid)


class SettingsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        card = ttk.LabelFrame(self, text=" Portable paths ", padding=10)
        card.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        wrap1 = ttk.Frame(card, style="TFrame")
        wrap1.pack(fill="both", expand=True)
        self.paths_text = add_text(wrap1, height=8)
        self.paths_text.insert("1.0", "starting…")

        mem = ttk.LabelFrame(self, text=" Recent memory (memory.md) ", padding=10)
        mem.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        wrap2 = ttk.Frame(mem, style="TFrame")
        wrap2.pack(fill="both", expand=True)
        self.memory_text = add_text(wrap2, height=10)

    def set_paths(self, mapping: dict):
        self.paths_text.configure(state="normal")
        self.paths_text.delete("1.0", "end")
        self.paths_text.insert("1.0", "\n".join(f"{k}: {v}" for k, v in mapping.items()))
        self.paths_text.configure(state="disabled")

    def refresh_memory(self, lines: list):
        self.memory_text.configure(state="normal")
        self.memory_text.delete("1.0", "end")
        self.memory_text.insert("1.0", "\n".join(lines) or "(empty)")
        self.memory_text.configure(state="disabled")
