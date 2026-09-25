#!/usr/bin/env python3
"""Launcher for the Malware Persistence Technique Cataloger.

    python run.py                 # start the GUI
    python run.py --selftest      # headless pipeline verification (all fixtures)
    python run.py --demo KIND     # analyse one fixture
    python run.py --analyze FILE  # analyse one report and export every format
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
