#!/usr/bin/env bash
# Build the portable one-file HashArmor executable (Linux/macOS; see
# build_exe.bat for Windows). Output: dist/HashArmor (or HashArmor.exe).
set -euo pipefail
cd "$(dirname "$0")"

python -m pip install --quiet "pyinstaller>=6.10,<7"

python -m PyInstaller --noconfirm --clean \
  --onefile --windowed \
  --name HashArmor \
  --add-data "assets/wordlists:assets/wordlists" \
  --hidden-import tkinter \
  --hidden-import tkinter.filedialog \
  --hidden-import tkinter.messagebox \
  main.py

echo
echo "Build complete -> dist/HashArmor"
