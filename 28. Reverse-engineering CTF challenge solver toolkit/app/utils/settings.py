"""Persistent GUI settings stored in data/settings.json."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from app.config import get_data_dir

_DEFAULTS: Dict[str, Any] = {
    "challenge_name": "",
    "category": "rev",
    "event": "",
    "description": "",
    "flag_format": "flag{",
    "binary_path": "",
    "last_encoding": "auto",
    "last_key": "",
}


class Settings:
    def __init__(self, path: str = ""):
        self.path = path or os.path.join(get_data_dir(), "settings.json")
        self.data: Dict[str, Any] = dict(_DEFAULTS)
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except Exception:
            pass

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default if default is not None else _DEFAULTS.get(key))

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def update(self, mapping: Dict[str, Any]) -> None:
        self.data.update(mapping)

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, self.path)
