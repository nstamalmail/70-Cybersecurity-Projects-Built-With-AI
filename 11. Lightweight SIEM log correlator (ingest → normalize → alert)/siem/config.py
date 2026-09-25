"""Configuration management.

Keeps the app portable: when frozen (PyInstaller) the app dir is the exe's
directory, otherwise the project root. All mutable data lives in ``data/``
next to the app, with an APPDATA fallback if that location is not writable.
"""
from __future__ import annotations

import json
import os
import sys

APP_NAME = "SIEMCorrelator"

DEFAULT_CONFIG = {
    "raw_queue_size": 10000,    # max raw events buffered between ingest and processor
    "max_events_kept": 50000,   # SQLite events ring-buffer cap
    "poll_interval": 0.5,       # file source poll seconds
    "syslog_port": 514,         # default port for udp sources
    "alert_beep": True,         # beep on new alert
    "max_events_rows": 5000,    # GUI live-events table cap
    "max_alerts_rows": 500,     # GUI alerts table cap
    # notifiers: optional list of alert outbound targets (see siem/notifiers.py).
    # Not present in defaults so a missing key is treated as "none configured".
}


def app_dir() -> str:
    """Directory that holds the application (exe dir when frozen)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_dir() -> str:
    """Writable data directory; falls back to %APPDATA%/SIEMCorrelator."""
    d = os.path.join(app_dir(), "data")
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".write_test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        return d
    except OSError:
        alt = os.path.join(
            os.environ.get("APPDATA") or os.path.expanduser("~"), APP_NAME
        )
        os.makedirs(alt, exist_ok=True)
        return alt


def load_config(path: str | None = None) -> dict:
    """Load config.json merged over defaults; writes the file if missing."""
    path = path or os.path.join(data_dir(), "config.json")
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        # Known tuning knobs are merged over defaults; the opaque ``notifiers``
        # list is preserved as-is so consumers can validate it themselves.
        cfg.update({k: v for k, v in stored.items() if k in DEFAULT_CONFIG})
        if isinstance(stored.get("notifiers"), list):
            cfg["notifiers"] = stored["notifiers"]
    except (OSError, ValueError):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2)
        except OSError:
            pass
    return cfg