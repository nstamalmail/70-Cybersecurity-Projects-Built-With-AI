"""User preference persistence (currently: UI theme).

Stored as JSON at %LOCALAPPDATA%\\VlsmPlanner\\config.json (packaged exe) or
./config.json (source checkout), written atomically. A missing or corrupt
file degrades to defaults — preferences must never crash the app.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

from .repository import atomic_write

CONFIG_FILENAME = "config.json"
VALID_THEMES = ("light", "dark")
DEFAULT_THEME = "light"


def config_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return os.path.join(base, "VlsmPlanner")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


def _path() -> str:
    return os.path.join(config_dir(), CONFIG_FILENAME)


def load_config() -> Dict[str, Any]:
    try:
        with open(_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: Dict[str, Any]) -> None:
    """Atomically persist config; propagates OSError/PersistenceError."""
    os.makedirs(config_dir(), exist_ok=True)
    atomic_write(_path(), json.dumps(data, indent=2))


def load_theme() -> str:
    theme = load_config().get("theme")
    return theme if theme in VALID_THEMES else DEFAULT_THEME


def save_theme(mode: str) -> None:
    mode = mode if mode in VALID_THEMES else DEFAULT_THEME
    cfg = load_config()
    cfg["theme"] = mode
    save_config(cfg)