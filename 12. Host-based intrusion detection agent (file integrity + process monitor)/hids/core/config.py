"""JSON configuration with schema defaults; stored in the portable data dir."""

import copy
import json
from pathlib import Path
from typing import Any

DEFAULTS: dict = {
    "version": 1,
    "scan_interval_seconds": 300,
    "process_poll_seconds": 10,
    "realtime_fim": True,
    "realtime_debounce_seconds": 1.0,
    "max_file_size_mb": 100,
    "monitored_paths": [],
    "exclude_patterns": [
        "*.tmp",
        "*.log",
        "*.lnk",
        "*/.git/*",
        "*/node_modules/*",
        "*/__pycache__/*",
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
    ],
    "process_blacklist": [
        "mimikatz.exe",
        "lazagne.exe",
        "lazagne.exe.exe",
        "pwdump.exe",
        "wce.exe",
        "procdump64.exe",
        "nc.exe",
        "ncat.exe",
        "netcat.exe",
        "nc64.exe",
        "chisel.exe",
        "ngrok.exe",
        "pupy.exe",
        "cobaltstrike.exe",
        "beacon.exe",
    ],
    "burst_threshold": 15,
    "burst_window_seconds": 60,
    "burst_cooldown_seconds": 300,
    "alert_retention_days": 30,
    "process_rules": {"alert_on_new_process": False},
    "process_alert_cooldown_seconds": 900,
}


class Config:
    """Config file with defaults-merge loading (corrupt file -> safe defaults)."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "config.json"
        self.data: dict = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(stored, dict):
            self.data = copy.deepcopy(DEFAULTS)
            self.data.update(stored)

    def save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.data:
            return self.data[key]
        return DEFAULTS.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
