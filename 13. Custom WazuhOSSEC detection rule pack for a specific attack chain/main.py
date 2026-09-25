"""Wazuh/OSSEC Rule Pack Builder — GUI entry point.

Run with:  python main.py
Build exe:  build_exe.bat  (or  build_exe.sh)
"""

from __future__ import annotations

import sys
import tkinter as tk

from app.ui.main_window import MainWindow


def main() -> None:
    root = tk.Tk()
    MainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    # PyInstaller windowed builds need this exact guard.
    if sys.platform == "win32":
        # Tk on Windows needs the DPI-aware flag for crisp text.
        try:
            from ctypes import windll  # type: ignore

            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass
    main()