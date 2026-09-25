#!/usr/bin/env python3
"""Launcher for the Dynamic Analysis Sandbox.

    python run.py                 # start the GUI
    python run.py --selftest      # headless pipeline verification
    python run.py --analyze FILE  # analyse one file and export reports
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.main import main  # noqa: E402

if __name__ == "__main__":
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    raise SystemExit(main())
