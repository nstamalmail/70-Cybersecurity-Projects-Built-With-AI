"""state.md — current snapshot (overwritten on save) + machine-readable JSON twin.

Also provides atomic-write and fingerprint helpers shared with memory.py.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

STATE_MD = "state.md"
LAST_SESSION_JSON = "state/last-session.json"


def atomic_write(path: str, text: str) -> None:
    """Write temp file then os.replace — never leaves a half-written file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-state-", suffix=".md")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fmt(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


class StateStore:
    """Saves/loads the exact last-session state (config + metrics + counters)."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.md_path = os.path.join(root, STATE_MD)
        self.json_path = os.path.join(root, LAST_SESSION_JSON)

    # ------------------------------------------------------------------ save
    def save(self, config, summary: Dict, events_count: int,
             note: str = "") -> None:
        fp = config.fingerprint()
        now = utc_now_iso()
        profiles = summary.get("profiles", {})
        server = summary.get("server", {})
        profiles_cfg = {p.name: p for p in config.profiles}

        lines: list[str] = []
        lines.append("# State — Agent Check-in Jitter/Sleep Study")
        lines.append("")
        lines.append("> Overwritten on every save. History lives in memory.md.")
        lines.append("")
        lines.append("```yaml")
        lines.append(f"schema_version: 1")
        lines.append(f"saved_at_utc: {now}")
        lines.append(f"config_fingerprint: {fp}")
        lines.append(f"elapsed_sim_s: {summary.get('elapsed_sim_s', 0.0):.3f}")
        lines.append(f"agents: {summary.get('agents', 0)}")
        lines.append(f"events_recorded: {events_count}")
        lines.append(f"run_counter: {self._next_run_counter()}")
        lines.append("```")
        lines.append("")

        lines.append("## Server config")
        lines.append("")
        lines.append("| key | value |")
        lines.append("|---|---|")
        for k, v in config.server.to_dict().items():
            lines.append(f"| {k} | {fmt(v)} |")
        lines.append("")

        lines.append("## Profiles")
        lines.append("")
        for name, prof in profiles_cfg.items():
            s = profiles.get(name, {})
            lines.append(f"### {name} — {prof.strategy}, "
                         f"base={prof.base_delay_s}s, jitter={prof.jitter_s}s, "
                         f"count={prof.agent_count}")
            lines.append("")
            lines.append("| metric | value |")
            lines.append("|---|---|")
            for k in ("agents", "checkins", "successes", "failures", "retries",
                      "interval_mean_s", "drift_p50_s", "drift_p95_s",
                      "drift_max_s"):
                lines.append(f"| {k} | {fmt(s.get(k))} |")
            lines.append("")

        lines.append("## Server totals")
        lines.append("")
        lines.append("| metric | value |")
        lines.append("|---|---|")
        for k in ("total", "ok", "rejected", "locked", "rejection_rate"):
            lines.append(f"| {k} | {fmt(server.get(k))} |")
        lines.append("")
        if note:
            lines.append(f"**Note:** {note}")
            lines.append("")
        lines.append(f"_Resume hint: open the GUI and press 'Load state', or "
                     f"recreate the run with `python cli.py --demo --record`._")
        lines.append("")

        atomic_write(self.md_path, "\n".join(lines))
        atomic_write(self.json_path, json.dumps({
            "schema_version": 1,
            "saved_at_utc": now,
            "config_fingerprint": fp,
            "config": config.to_dict(),
            "summary": summary,
            "events_recorded": events_count,
            "note": note,
        }, indent=2, sort_keys=True))

    # ------------------------------------------------------------------ load
    def load(self) -> Optional[Dict]:
        if not os.path.exists(self.json_path):
            return None
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def load_config(self):
        from core.config import AppConfig
        data = self.load()
        if not data:
            return None
        return AppConfig.from_dict(data.get("config", {}))

    # --------------------------------------------------------------- counter
    def _next_run_counter(self) -> int:
        # memory.md run count + 1; kept simple and robust
        mem_path = os.path.join(self.root, "memory.md")
        n = 0
        if os.path.exists(mem_path):
            with open(mem_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("## Run "):
                        n += 1
        return n + 1
