"""API Call Sequence Visualizer - metadata and portable runtime paths.

Everything app-specific lives in ``APP`` below.  The rest of this module is the
shared runtime layer (portable data directory, settings store) used by every
module in the application, and is identical across the workbench suite so that
each tool behaves the same way when frozen into a portable executable.

Data location policy (portable first):
  1. ``<folder containing the exe or source> / data``  - used when writable, so a
     portable build keeps its cases, parsed reports, patterns and logs next to
     the executable.
  2. ``%LOCALAPPDATA%/<slug>`` on Windows, ``~/.local/share/<slug>`` elsewhere -
     used when the portable directory is read-only.
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
    "slug": "acsv",
    "acronym": "ACSV",
    "exe": "ACSV-ApiSequenceVisualizer",
    "name": "API Sequence Visualizer",
    "title": "API Call Sequence Visualizer",
    "subtitle": "Cuckoo / CAPE report ingestion \\u00b7 process tree \\u00b7 behaviour timeline \\u00b7 sequence patterns",
    "version": "1.0.0",
    "vendor": "Malware Analysis Workbench",
    "report_title": "API Call Sequence Analysis Report",
    "artifact_noun": "report",
    "accent": "#38bdf8",
    "accent_dim": "#123047",
    "file_filters": [
        ("Sandbox reports (*.json *.jsonl *.bson *.log *.log.bson)", "*.json *.jsonl *.bson *.log"),
        ("All files (*)", "*"),
    ],
    "description": (
        "Ingests Cuckoo / CAPE behaviour reports (JSON and CAPE BSON logs), normalises "
        "every API call, rebuilds the process tree, collapses loops, matches behavioural "
        "sequence patterns (injection, credential access, persistence, beaconing, "
        "ransomware) and turns it into a navigable timeline with per-call evidence, "
        "filters, a category heatmap and an exported analysis report."
    ),
    "timeline_categories": ("process", "memory", "file", "registry", "network", "crypto"),
    "settings": {
        "max_calls": 2_000_000,           # hard cap when parsing a report
        "collapse_loops": True,
        "collapse_threshold": 3,
        "mine_max_calls": 120_000,        # sample size for n-gram / Markov mining
        "ngram_sizes": (2, 3, 4, 5),
        "ngram_min_occurrences": 2,
        "ngram_top": 60,
        "ngram_per_process": False,
        "cluster_min_support": 2,
        "cluster_top": 25,
        "markov_top": 400,
        "markov_per_process": False,
        "match_limit": 4000,
        "burst_window": 1.0,
        "burst_threshold": 40,
        "timeline_buckets": 120,
        "heatmap_min_calls": 1,
        "ignore_categories": [],          # e.g. ["system", "sync"] to reduce noise
        "pattern_min_severity": "low",
        "ioc_min_confidence": 0.0,
        "redact_exports": False,
        "store_sqlite": True,
        "fixture_calls": 420,
    },
    "severities": ["critical", "high", "medium", "low", "info"],
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
        probe = path / ".acsv_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def data_root() -> Path:
    """Root directory for all generated state (cases, patterns, reports, logs)."""
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


def patterns_dir() -> Path:
    """User pattern library (JSON or YAML files are both accepted)."""
    return _sub("patterns")


def case_db_path() -> Path:
    return data_root() / "cases.db"


def settings_path() -> Path:
    return data_root() / "settings.json"


# --------------------------------------------------------------------------- #
#  Settings store
# --------------------------------------------------------------------------- #
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
    """Tiny JSON-backed settings store with defaults."""

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
            settings_path().write_text(json.dumps(self._data, indent=2), encoding="utf-8")
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
