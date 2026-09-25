"""VLSM Planner — entry point.

Run from source:        python main.py
Build portable exe:     pyinstaller --noconfirm --clean --onefile --windowed \
                          --name "VLSM-Planner" --distpath dist --workpath build main.py
"""

from __future__ import annotations

import sys


def main() -> int:
    from src.app import AppController
    from src.ui.main_window import MainWindow
    from src.util.logging_setup import configure_logging

    configure_logging()
    app = AppController()
    window = MainWindow(app)
    window.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())