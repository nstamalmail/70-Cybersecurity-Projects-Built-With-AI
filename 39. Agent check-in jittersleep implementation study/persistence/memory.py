"""memory.md — append-only run history, plus per-run JSON exports (runs/)."""
from __future__ import annotations

import itertools
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from .state import atomic_write, utc_now_iso, fmt

_RUN_SEQ = itertools.count(1)

MEMORY_MD = "memory.md"
RUNS_DIR = "runs"


class MemoryStore:
    """Append-only history of completed runs; never removes or rewrites entries."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.md_path = os.path.join(root, MEMORY_MD)
        self.runs_dir = os.path.join(root, RUNS_DIR)

    # ------------------------------------------------------------- append run
    def append_run(self, config, summary: Dict, events: Optional[List[Dict]] = None,
                   export_json: bool = True) -> str:
        """Append a run entry to memory.md; optionally export full JSON.

        Returns the run id (timestamp-based).
        """
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{next(_RUN_SEQ)}"
        prof = summary.get("profiles", {})
        srv = summary.get("server", {})

        lines: List[str] = []
        lines.append(f"## Run {run_id}")
        lines.append("")
        lines.append("```yaml")
        lines.append(f"recorded_at_utc: {utc_now_iso()}")
        lines.append(f"config_fingerprint: {config.fingerprint()}")
        lines.append(f"agents: {summary.get('agents', 0)}")
        lines.append(f"elapsed_sim_s: {summary.get('elapsed_sim_s', 0.0):.3f}")
        lines.append(f"events: {sum(1 for _ in (events or [])) if events is not None else 'n/a'}")
        lines.append("```")
        lines.append("")
        lines.append("| profile | agents | checkins | successes | retries | "
                     "interval_mean_s | drift_p95_s |")
        lines.append("|---|---|---|---|---|---|---|")
        for name, s in prof.items():
            lines.append(
                f"| {name} | {fmt(s.get('agents'))} | {fmt(s.get('checkins'))} | "
                f"{fmt(s.get('successes'))} | {fmt(s.get('retries'))} | "
                f"{fmt(s.get('interval_mean_s'))} | {fmt(s.get('drift_p95_s'))} |")
        lines.append("")
        lines.append(f"Server: total={fmt(srv.get('total'))} "
                     f"rejected={fmt(srv.get('rejected'))} "
                     f"locked={fmt(srv.get('locked'))} "
                     f"rejection_rate={fmt(srv.get('rejection_rate'))}")
        lines.append("")

        existing = ""
        if os.path.exists(self.md_path):
            with open(self.md_path, "r", encoding="utf-8") as f:
                existing = f.read()
        header_needed = not existing
        notes_needed = "## Notes" not in existing

        d = os.path.dirname(self.md_path)
        os.makedirs(d, exist_ok=True)
        with open(self.md_path, "a", encoding="utf-8") as f:
            if header_needed:
                f.write("# Memory — Agent Check-in Jitter/Sleep Study\n\n"
                        "> Append-only run history. Nothing is ever removed.\n\n")
            f.write("\n".join(lines))
            if notes_needed:
                f.write("\n## Notes\n\n- (edit freely)\n")

        if export_json:
            self.export_run(config, summary, events or [], run_id)
        return run_id

    # ------------------------------------------------------------- json export
    def export_run(self, config, summary: Dict, events: List[Dict],
                   run_id: Optional[str] = None) -> str:
        os.makedirs(self.runs_dir, exist_ok=True)
        run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(self.runs_dir, f"run_{run_id}.json")
        payload = {
            "schema_version": 1,
            "run_id": run_id,
            "recorded_at_utc": utc_now_iso(),
            "config_fingerprint": config.fingerprint(),
            "config": config.to_dict(),
            "summary": summary,
            "events": events,
        }
        atomic_write(path, json.dumps(payload))
        return path

    # ------------------------------------------------------------------- notes
    def ensure_notes_section(self) -> None:
        """Create memory.md with a Notes section if it doesn't exist yet."""
        if not os.path.exists(self.md_path):
            atomic_write(self.md_path,
                         "# Memory — Agent Check-in Jitter/Sleep Study\n\n"
                         "> Append-only run history. Nothing is ever removed.\n\n"
                         "## Notes\n\n- (edit freely)\n")
