"""CSV export: profile-level metrics table and per-agent stats.

Two files, written as a pair on export:
  metrics_<run_id>.csv  — one row per profile (what the GUI Metrics tab shows)
  agents_<run_id>.csv   — one row per agent (raw counters, failures/retries separate)
"""
from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from typing import Dict, List, Optional

from .state import atomic_write

PROFILE_FIELDS = [
    "run_id", "profile", "agents", "checkins", "successes", "failures",
    "retries", "interval_mean_s", "interval_std_s", "drift_p50_s",
    "drift_p95_s", "drift_max_s",
]

AGENT_FIELDS = [
    "agent_id", "profile", "checkins", "successes", "failures", "retries",
    "interval_mean_s", "interval_std_s", "interval_min_s", "interval_max_s",
    "drift_mean_s", "drift_p50_s", "drift_p95_s", "drift_max_s",
    "attempts_p50", "attempts_p95",
]


def _fmt(v) -> str:
    """None -> empty cell; floats with 6 decimal places; else str."""
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.6f}"
    return str(v)


def render_csv(fields: List[str], rows: List[Dict]) -> str:
    """Render rows to CSV text (exposed for tests)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(fields)
    for r in rows:
        w.writerow([_fmt(r.get(f)) for f in fields])
    return buf.getvalue()


def write_csv(path: str, fields: List[str], rows: List[Dict]) -> None:
    atomic_write(path, render_csv(fields, rows))


def _new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _profile_rows(summary: Dict, run_id: str) -> List[Dict]:
    """One row per profile from a fleet summary."""
    rows = []
    for name, s in summary.get("profiles", {}).items():
        row = {"run_id": run_id, "profile": name}
        row.update(s)
        rows.append(row)
    return rows


def export_profile_metrics(summary: Dict, run_id: Optional[str] = None,
                           out_dir: str = "runs") -> str:
    """Write metrics_<run_id>.csv (one row per profile); returns the path."""
    os.makedirs(out_dir, exist_ok=True)
    run_id = run_id or _new_run_id()
    path = os.path.join(out_dir, f"metrics_{run_id}.csv")
    write_csv(path, PROFILE_FIELDS, _profile_rows(summary, run_id))
    return path


def export_agent_stats(collector, run_id: Optional[str] = None,
                       out_dir: str = "runs") -> str:
    """Write agents_<run_id>.csv (one row per agent); returns the path.

    `collector` is a core.metrics.MetricsCollector.
    """
    os.makedirs(out_dir, exist_ok=True)
    run_id = run_id or _new_run_id()
    path = os.path.join(out_dir, f"agents_{run_id}.csv")
    rows = [m.stat_row() for m in collector.all()]
    write_csv(path, AGENT_FIELDS, rows)
    return path


def export_all(summary: Dict, collector, run_id: Optional[str] = None,
               out_dir: str = "runs") -> List[str]:
    """Export both files; returns their paths."""
    run_id = run_id or _new_run_id()
    return [
        export_profile_metrics(summary, run_id, out_dir),
        export_agent_stats(collector, run_id, out_dir),
    ]


def split_base(path: str) -> "tuple[str, str]":
    """Split a user-chosen path into (base, ext), stripping known pair suffixes.

    'C:/out/run.csv'      -> ('C:/out/run', '.csv')
    'C:/out/run_metrics'  -> ('C:/out/run', '.csv')
    'C:/out/run_agents.csv' -> ('C:/out/run', '.csv')
    """
    root, ext = os.path.splitext(path)
    ext = ext.lower()
    if ext != ".csv":
        # tolerate a missing/odd extension; default to .csv
        root = (root + ext) if ext else root
        ext = ".csv"
    for suffix in ("_metrics", "_agents"):
        if root.endswith(suffix):
            root = root[: -len(suffix)]
            break
    return root, ext


def export_all_to_base(summary: Dict, collector, base: str) -> List[str]:
    """Export the pair as <base>_metrics.csv and <base>_agents.csv.

    `base` comes from the GUI save dialog (any extension/suffix is tolerated;
    see split_base). Existing files are overwritten. Returns the paths.
    """
    root, ext = split_base(base)
    os.makedirs(os.path.dirname(os.path.abspath(root)) or ".", exist_ok=True)
    paths = [root + "_metrics" + ext, root + "_agents" + ext]
    write_csv(paths[0], PROFILE_FIELDS,
              _profile_rows(summary, run_id=os.path.basename(root)))
    write_csv(paths[1], AGENT_FIELDS,
              [m.stat_row() for m in collector.all()])
    return paths
