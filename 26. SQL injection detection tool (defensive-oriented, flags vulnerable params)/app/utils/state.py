"""StateStore: maintains state.md (live) and memory.md (append-only log)."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from app.config import get_base_dir

_STATE_HEADER = "# SIDT — Live State\n\n"
_MEMORY_HEADER = (
    "# SIDT — Project Memory\n\n"
    "Append-only log of sessions, scans, findings and decisions.\n"
    "Timestamps are local time.\n\n"
)


class StateStore:
    def __init__(self, base_dir: Optional[str] = None):
        base = base_dir or get_base_dir()
        self.state_path = os.path.join(base, "state.md")
        self.memory_path = os.path.join(base, "memory.md")
        self._ensure_memory()

    def _ensure_memory(self) -> None:
        if not os.path.exists(self.memory_path):
            with open(self.memory_path, "w", encoding="utf-8") as fh:
                fh.write(_MEMORY_HEADER)

    # ------------------------------------------------------------------- state.md
    def write_state(self, fields: Dict[str, Any]) -> None:
        lines = [_STATE_HEADER]
        for key, value in fields.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")
        lines.append("This file is machine-maintained. See `memory.md` for history.")
        lines.append("")
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        os.replace(tmp, self.state_path)

    # ----------------------------------------------------------------- memory.md
    def log_memory(self, entry: str) -> None:
        with open(self.memory_path, "a", encoding="utf-8") as fh:
            fh.write(f"- [{self._ts()}] {entry}\n")

    @staticmethod
    def _ts() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def read_memory(self, limit: int = 40) -> List[str]:
        try:
            with open(self.memory_path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.startswith("- [")]
        except Exception:
            return []
        return lines[-limit:]


def write_initial_state() -> None:
    StateStore().write_state({
        "App": "SIDT GUI",
        "Status": "idle",
        "Last activity": StateStore._ts(),
        "Current scan": "none",
    })
