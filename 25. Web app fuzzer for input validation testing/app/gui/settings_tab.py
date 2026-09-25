"""Tab 6: Settings — app paths, state/memory viewer."""

from __future__ import annotations

from tkinter import ttk

from app.gui.widgets import Card, add_text


class SettingsTab(ttk.Frame):
    def __init__(self, master, paths: dict = None):
        super().__init__(master, style="TFrame")
        self.paths = paths or {}
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        paths = Card(self, "Paths & persistence")
        paths.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        self._paths_row = ttk.Frame(paths.inner, style="TFrame")
        self._paths_row.pack(fill="x")
        self._render_paths()

        mem = Card(self, "Project memory (tail of memory.md)")
        mem.grid(row=1, column=0, sticky="nsew", padx=10, pady=(5, 10))
        self.mem_text = add_text(mem.inner, height=14)
        self.mem_text.configure(state="disabled")

    def _render_paths(self) -> None:
        for w in self._paths_row.winfo_children():
            w.destroy()
        for i, key in enumerate(self.paths):
            row = i % 2
            col = (i // 2) * 2
            lbl = ttk.Label(self._paths_row, text=f"{key}:")
            val = ttk.Label(self._paths_row, text=str(self.paths.get(key, "")),
                            foreground="#a6e3a1", wraplength=560)
            if row == 0 and col == 0:
                lbl.grid(row=0, column=0, sticky="w")
                val.grid(row=0, column=1, sticky="w", padx=(0, 20))
            else:
                lbl.grid(row=row, column=col, sticky="w", padx=(0, 6))
                val.grid(row=row, column=col + 1, sticky="w", padx=(0, 20))

    def set_paths(self, paths: dict) -> None:
        self.paths = paths
        if hasattr(self, "_paths_row"):
            self._render_paths()

    def refresh_memory(self, lines: list) -> None:
        self.mem_text.configure(state="normal")
        self.mem_text.delete("1.0", "end")
        self.mem_text.insert("1.0", "\n".join(lines) or "(no memory entries yet)")
        self.mem_text.configure(state="disabled")