"""Static Analysis Pipeline - application metadata and portable runtime paths.

Everything app-specific lives in ``APP`` below.  The rest of this module is the
shared runtime layer (portable data directory, settings store) used by every
other module in the application, and is identical across the workbench suite so
that each tool behaves the same way when frozen into a portable executable.

Data location policy (portable first):
  1. ``<folder containing the exe or source> / data``  - used when writable, so a
     portable build keeps its cases, reports and logs next to the executable.
  2. ``%LOCALAPPDATA%/<slug>`` on Windows, ``~/.local/share/<slug>`` elsewhere -
     used when the portable directory is read-only (e.g. running from a CD or a
     locked-down Program Files install).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
#  Application metadata - the only app-specific block in this module.
# --------------------------------------------------------------------------- #
APP: dict = {
    "slug": "sap",
    "acronym": "SAP",
    "name": "Static Analysis Pipeline",
    "title": "Static Analysis Pipeline",
    "subtitle": "Hash \u00b7 PE header parsing \u00b7 string extraction \u00b7 threat-intel verdict",
    "version": "1.0.0",
    "vendor": "Malware Analysis Workbench",
    "report_title": "Static Analysis Report",
    "artifact_noun": "sample",
    "accent": "#4da3ff",
    "accent_dim": "#1d3450",
    "file_filters": [
        ("Executables (*.exe *.dll *.sys *.scr *.bin)", "*.exe *.dll *.sys *.scr *.bin"),
        ("All files (*)", "*"),
    ],
    "description": (
        "Read-only first-pass triage of suspicious Windows executables: hashing, "
        "PE header parsing, string extraction with pattern classification, IOC "
        "compilation and a weighted MALICIOUS / SUSPICIOUS / LIKELY CLEAN verdict."
    ),
    # Workbench specific defaults, merged into DEFAULT_SETTINGS below.
    "settings": {
        "min_string_length": 4,
        "entropy_threshold": 7.0,
    },
    "verdict_thresholds": {"malicious": 60, "suspicious": 25},
}

FROZEN: bool = bool(getattr(sys, "frozen", False))

_data_root_cache: Path | None = None


# --------------------------------------------------------------------------- #
#  Paths
# --------------------------------------------------------------------------- #
def project_root() -> Path:
    """Directory holding the executable (frozen) or the source tree (dev)."""
    if FROZEN:
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".sap_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def data_root() -> Path:
    """Root directory for all generated state (cases, reports, logs, cache)."""
    global _data_root_cache
    if _data_root_cache is not None:
        return _data_root_cache

    portable = project_root() / "data"
    if _is_writable(portable):
        _data_root_cache = portable
        return portable

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    fallback = base / APP["slug"]
    fallback.mkdir(parents=True, exist_ok=True)
    _data_root_cache = fallback
    return fallback


def _sub(name: str) -> Path:
    p = data_root() / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def reports_dir() -> Path:
    return _sub("reports")


def logs_dir() -> Path:
    return _sub("logs")


def cases_dir() -> Path:
    return _sub("cases")


def cache_dir() -> Path:
    return _sub("cache")


def demo_dir() -> Path:
    return _sub("demo")


def exports_dir() -> Path:
    p = data_root() / "exports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def settings_path() -> Path:
    return data_root() / "settings.json"


# --------------------------------------------------------------------------- #
#  Settings store
# --------------------------------------------------------------------------- #
# Generic defaults shared by every workbench; APP["settings"] adds the
# workbench specific ones on top.
DEFAULT_SETTINGS: dict = {
    "max_file_size_mb": 500,
    "enable_network_lookups": False,
    "virustotal_api_key": "",
    "malwarebazaar_api_key": "",
    "otx_api_key": "",
    "theme": "dark",
    "redact_exports": False,
    "interactive_dialogs": True,
    "analyst": os.environ.get("USERNAME") or os.environ.get("USER") or "analyst",
}
DEFAULT_SETTINGS.update(APP.get("settings", {}))


class Settings:
    """Tiny JSON-backed settings store with defaults and change notification."""

    def __init__(self, defaults: dict | None = None) -> None:
        self._defaults = dict(defaults or DEFAULT_SETTINGS)
        self._data: dict = dict(self._defaults)
        self.load()

    def load(self) -> None:
        path = settings_path()
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data.update(loaded)
            except Exception:
                pass

    def save(self) -> None:
        try:
            settings_path().write_text(
                json.dumps(self._data, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def get(self, key: str, default=None):
        return self._data.get(key, self._defaults.get(key, default))

    def set(self, key: str, value) -> None:
        self._data[key] = value

    def update(self, values: dict) -> None:
        self._data.update(values)

    def as_dict(self) -> dict:
        return dict(self._data)


SETTINGS = Settings()
