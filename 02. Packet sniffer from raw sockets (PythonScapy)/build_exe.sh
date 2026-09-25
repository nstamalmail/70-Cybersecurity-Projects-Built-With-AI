#!/usr/bin/env bash
# ============================================================
#  PacketSniffer - build script (Linux/macOS sanity build)
#  Produces dist/PacketSniffer (onefile binary for this OS).
# ============================================================
set -e
cd "$(dirname "$0")"

echo "[1/3] Ensuring PyInstaller is available..."
python -m pip show pyinstaller >/dev/null 2>&1 || python -m pip install --quiet pyinstaller

echo "[2/3] Running unit tests..."
python -m unittest discover -s tests || true

echo "[3/3] Building..."
python -m PyInstaller sniffer.spec --noconfirm

echo
echo "Build OK: dist/PacketSniffer"
echo "SHA256:"
sha256sum dist/PacketSniffer || shasum -a 256 dist/PacketSniffer
