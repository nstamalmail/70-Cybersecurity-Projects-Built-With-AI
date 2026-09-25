"""Application-level configuration and path resolution (PyInstaller-aware)."""

import os
import shutil
import sys

APP_NAME = "WNA"
VERSION = "1.0.0"

SAMPLES_FOLDER = "samples"


def get_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir() -> str:
    d = os.path.join(get_base_dir(), "data")
    os.makedirs(d, exist_ok=True)
    return d


def get_reports_dir() -> str:
    d = os.path.join(get_base_dir(), "reports")
    os.makedirs(d, exist_ok=True)
    return d


def get_bundled_samples_dir() -> str:
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
        return os.path.join(meipass, SAMPLES_FOLDER)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), SAMPLES_FOLDER)


def ensure_samples_dir() -> str:
    base = get_base_dir()
    dest = os.path.join(base, SAMPLES_FOLDER)
    src = get_bundled_samples_dir()

    if not getattr(sys, "frozen", False):
        if src != dest and os.path.isdir(dest):
            return dest
        return src

    os.makedirs(dest, exist_ok=True)
    if os.path.isdir(src):
        for name in os.listdir(src):
            s = os.path.join(src, name)
            d = os.path.join(dest, name)
            if os.path.isfile(s) and not os.path.exists(d):
                try:
                    shutil.copy2(s, d)
                except Exception:
                    pass
    return dest


SAMPLES_DIR = ensure_samples_dir()
