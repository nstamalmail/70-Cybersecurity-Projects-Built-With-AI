"""Logs tab: live engine log stream."""

import tkinter as tk
from tkinter import ttk

MAX_LINES = 3000


class LogsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=10)
        self.app = app
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 4))
        self.autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-scroll", variable=self.autoscroll).pack(side="left")
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=6)
        self.text = tk.Text(self, wrap="none", font=("Consolas", 9),
                            bg="#101418", fg="#d4d4d4")
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.text["state"] = "disabled"

    def append(self, line: str):
        self.text["state"] = "normal"
        self.text.insert("end", line + "\n")
        if float(self.text.index("end-1c").split(".")[0]) > MAX_LINES:
            self.text.delete("1.0", "2.0")
        if self.autoscroll.get():
            self.text.see("end")
        self.text["state"] = "disabled"

    def clear(self):
        self.text["state"] = "normal"
        self.text.delete("1.0", "end")
        self.text["state"] = "disabled"
