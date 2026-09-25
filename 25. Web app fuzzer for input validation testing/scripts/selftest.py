#!/usr/bin/env python3
"""Run the headless engine self-test. Usage: python scripts/selftest.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools.selftest import run_selftest  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(run_selftest())