# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the portable PacketSniffer.exe.

Build:  pyinstaller sniffer.spec --noconfirm
Output: dist\PacketSniffer.exe  (single portable file)

Deliberately NOT requireAdministrator: the exe must open for offline
.pcap analysis without elevation; live capture re-launches elevated.
"""

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("tests/fixtures/sample.pcap", "sample")],
    hiddenimports=[
        "sniffer",
        "sniffer.gui.app",
        "sniffer.gui.panels",
        "sniffer.gui.stats_panel",
        "sniffer.gui.dialogs",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "pytest", "setuptools", "pip", "wheel", "pkg_resources",
        "numpy", "pandas", "scapy", "matplotlib", "IPython", "jedi",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PacketSniffer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                      # windowed GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,                          # optional: "assets/icon.ico"
)
