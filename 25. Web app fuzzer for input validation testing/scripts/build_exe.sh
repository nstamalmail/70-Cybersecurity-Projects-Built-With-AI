#!/usr/bin/env bash
# Build a portable single-file Windows exe with PyInstaller.
# Run from the project root:  bash scripts/build_exe.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_SRC="$(cd "$SCRIPT_DIR/.." && pwd)/samples"

PY=python
if [ -d ".venv" ]; then
  if [ -f ".venv/Scripts/python" ]; then PY=".venv/Scripts/python"; else PY=".venv/bin/python"; fi
fi

echo "==> Installing build deps (dev)"
"$PY" -m pip install -r requirements.txt -r requirements-dev.txt

echo "==> Running engine self-test before packaging"
"$PY" scripts/selftest.py

echo "==> Building WebFuzzer.exe (onefile, windowed, samples bundled)"
"$PY" -m PyInstaller --noconfirm --clean \
    --onefile --windowed --name WebFuzzer \
    --add-data "$SAMPLES_SRC;samples" \
    main.py

echo "==> Verifying the portable exe headlessly"
./dist/WebFuzzer.exe --selftest

echo "==> Done. Portable exe: dist/WebFuzzer.exe"
