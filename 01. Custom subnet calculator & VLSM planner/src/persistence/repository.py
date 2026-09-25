"""Plan persistence: strict schema-validated JSON and human-readable reports.

Security notes (see architecture.md §3):
- Data only, never code: we use `json`, never pickle/eval.
- Every field is validated on load (types, ranges, caps) before it can reach
  the allocator, so a hand-crafted or corrupted file cannot exhaust memory or
  produce nonsense results.
- Writes are atomic (temp file + os.replace) so a crash never leaves a
  half-written plan behind.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict

from ..domain.calculator import network_from_string
from ..domain.models import PersistenceError, VlsmPlan, VlsmSegment
from ..domain.vlsm import MAX_SEGMENTS, plan_vlsm

FORMAT_TAG = "vlsm-plan"
SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Save
# --------------------------------------------------------------------------

def save_plan(path: str, plan: VlsmPlan) -> None:
    """Serialize a VlsmPlan to JSON atomically."""
    payload = {
        "format": FORMAT_TAG,
        "schema_version": SCHEMA_VERSION,
        "base_network": plan.base_network,
        "segments": [
            {
                "name": seg.name,
                "required_hosts": seg.required_hosts,
                "prefix": seg.prefix,
                "network": seg.network,
                "usable_hosts": seg.usable_hosts,
                "wasted_hosts": seg.wasted_hosts,
            }
            for seg in plan.segments
        ],
    }
    try:
        data = json.dumps(payload, indent=2)
    except (TypeError, ValueError) as exc:
        raise PersistenceError(f"Could not serialize plan: {exc}") from exc

    atomic_write(path, data)


def atomic_write(path: str, data: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".vlsm-plan-", suffix=".tmp", dir=directory)
    try:
        # newline="" disables Windows newline translation so callers control
        # line endings exactly (csv_io emits CRLF; reports/JSON emit LF).
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)  # atomic on the same filesystem
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise PersistenceError(f"Could not write plan to '{path}': {exc}") from exc


# --------------------------------------------------------------------------
# Load
# --------------------------------------------------------------------------

def load_plan(path: str) -> VlsmPlan:
    """Load and strictly validate a plan file. Raises PersistenceError."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw: Any = json.load(handle)
    except FileNotFoundError:
        raise PersistenceError(f"File not found: '{path}'") from None
    except json.JSONDecodeError as exc:
        raise PersistenceError(f"'{path}' is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise PersistenceError(f"Could not read '{path}': {exc}") from exc

    return _validate_payload(raw, path)


def _validate_payload(raw: Any, path: str) -> VlsmPlan:
    if not isinstance(raw, dict):
        raise PersistenceError(f"'{path}': plan file must contain a JSON object.")
    if raw.get("format") != FORMAT_TAG:
        raise PersistenceError(
            f"'{path}': not a VLSM planner file (missing format tag '{FORMAT_TAG}')."
        )
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise PersistenceError(
            f"'{path}': unsupported schema version "
            f"{raw.get('schema_version')!r} (expected {SCHEMA_VERSION})."
        )

    base_text = raw.get("base_network")
    if not isinstance(base_text, str):
        raise PersistenceError(f"'{path}': 'base_network' must be a string.")
    try:
        base = network_from_string(base_text)
    except ValueError as exc:
        raise PersistenceError(f"'{path}': invalid base_network: {exc}") from exc

    segs_raw = raw.get("segments")
    if not isinstance(segs_raw, list):
        raise PersistenceError(f"'{path}': 'segments' must be a list.")
    if not 1 <= len(segs_raw) <= MAX_SEGMENTS:
        raise PersistenceError(
            f"'{path}': segment count {len(segs_raw)} out of range (1..{MAX_SEGMENTS})."
        )

    # Rebuild the plan from the ground truth (name + required_hosts) and let
    # the allocator re-derive everything. Stored derived fields are ignored —
    # this is the strongest defense against hand-edited files.
    rows: list[tuple[str, int]] = []
    for idx, seg in enumerate(segs_raw, start=1):
        if not isinstance(seg, dict):
            raise PersistenceError(f"'{path}': segment {idx} is not an object.")
        name = seg.get("name")
        hosts = seg.get("required_hosts")
        if not isinstance(name, str) or not isinstance(hosts, int) or isinstance(hosts, bool):
            raise PersistenceError(
                f"'{path}': segment {idx} needs a string 'name' and an integer "
                f"'required_hosts'."
            )
        if not 1 <= hosts <= 2 ** 32 - 2:
            raise PersistenceError(
                f"'{path}': segment {idx} host count {hosts} out of range."
            )
        rows.append((name, hosts))

    try:
        return plan_vlsm(str(base), rows)
    except ValueError as exc:
        raise PersistenceError(
            f"'{path}': plan is inconsistent — {exc}"
        ) from exc


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def export_report(path: str, plan: VlsmPlan) -> None:
    """Write a human-readable, aligned plain-text report of the plan."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("VLSM PLAN REPORT")
    lines.append(f"Generated : {_now_iso()}")
    lines.append(f"Base      : {plan.base_network}")
    lines.append("=" * 78)
    lines.append("")
    header = (
        f"{'Segment':<22}{'Req hosts':>10}{'Prefix':>8}{'Network':>16}"
        f"{'Usable':>8}{'Wasted':>8}"
    )
    lines.append(header)
    lines.append("-" * 78)
    for seg in plan.segments:
        lines.append(
            f"{seg.name:<22}{seg.required_hosts:>10}{'/' + str(seg.prefix):>8}"
            f"{seg.network:>16}{seg.usable_hosts:>8}{seg.wasted_hosts:>8}"
        )
    lines.append("-" * 78)
    lines.append(
        f"{'TOTAL':<22}{plan.total_required:>10}{'':>8}{'':>16}"
        f"{plan.total_allocated:>8}{plan.total_wasted:>8}"
    )
    lines.append("")
    lines.append(
        f"Total address space allocated : {plan.total_allocated} "
        f"(of {2 ** (32 - int(plan.base_network.split('/')[1]))})"
    )
    lines.append(f"Total hosts required         : {plan.total_required}")
    lines.append(f"Total hosts wasted           : {plan.total_wasted}")
    lines.append(f"Allocation efficiency        : {plan.efficiency * 100:.2f}%")
    lines.append("")
    lines.append("Note: usable host counts follow RFC 3021 for /31 and /32.")
    lines.append("=" * 78)

    try:
        atomic_write(path, "\n".join(lines) + "\n")
    except PersistenceError:
        raise


def plan_to_dict(plan: VlsmPlan) -> Dict[str, Any]:
    """Expose the plan as a plain dict (used by the UI summary + tests)."""
    return {
        "base_network": plan.base_network,
        "total_required": plan.total_required,
        "total_allocated": plan.total_allocated,
        "total_wasted": plan.total_wasted,
        "efficiency": plan.efficiency,
    }