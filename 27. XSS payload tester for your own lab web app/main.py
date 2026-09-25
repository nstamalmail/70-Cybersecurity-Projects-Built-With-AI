"""XPT (XSS Payload Tester) entry point.

Usage:
    python main.py                 # launch GUI
    python main.py --selftest      # headless engine verification (no GUI)
"""

import sys


def main() -> int:
    if "--selftest" in sys.argv:
        from app.tools.selftest import run_selftest
        return run_selftest()

    from app.gui.main_window import run_gui
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
