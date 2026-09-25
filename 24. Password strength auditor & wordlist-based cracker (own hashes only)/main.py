"""HashArmor entrypoint.

    python main.py              # launch GUI
    python main.py --selftest   # run core self-tests and exit
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="HashArmor",
        description="Offline password strength auditor & wordlist-based cracker "
                    "(own hashes only).")
    ap.add_argument("--selftest", action="store_true",
                    help="run the core self-test suite and exit")
    args = ap.parse_args()

    if args.selftest:
        from core.selftest import run_selftest
        ok, report = run_selftest()
        print(report)
        return 0 if ok else 1

    # GUI
    from gui.app import HashArmorApp
    app = HashArmorApp()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
