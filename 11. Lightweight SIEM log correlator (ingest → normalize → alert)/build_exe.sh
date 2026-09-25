#!/usr/bin/env bash
# Build a portable single-file executable with PyInstaller.
# Result: dist/SIEMCorrelator(.exe on Windows)
set -euo pipefail
cd "$(dirname "$0")"
python -m PyInstaller --noconfirm --clean --onefile --windowed --name SIEMCorrelator main.py
echo "Build complete: dist/SIEMCorrelator"