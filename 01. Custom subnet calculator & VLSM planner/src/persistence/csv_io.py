"""CSV import/export for VLSM segment lists and allocation results.

Formats
-------
Segments (round-trippable, matches the requirements table):

    name,required_hosts
    mgmt,10
    users,120

Import is lenient: a header row is auto-detected and skipped, files without
a header work, blank lines are ignored, and every data row is validated with
the same bounds as the allocator (name length, host-count range, row cap) so
a hostile or malformed CSV fails fast instead of producing garbage.

Results (export only, one row per allocated segment):

    segment,required_hosts,prefix,network,netmask,usable_hosts,wasted_hosts

Security: data only (stdlib `csv`), no dynamic code; writes are atomic via
repository.atomic_write.
"""

from __future__ import annotations

import csv
import io
from typing import Iterable, List, Sequence, Tuple

from ..domain.calculator import netmask_from_prefix
from ..domain.models import PersistenceError, VlsmPlan
from ..domain.vlsm import MAX_NAME_LENGTH, MAX_SEGMENTS
from .repository import atomic_write

REQ_HEADER = ["name", "required_hosts"]
RESULT_HEADER = [
    "segment", "required_hosts", "prefix", "network",
    "netmask", "usable_hosts", "wasted_hosts",
]
# One header row plus MAX_SEGMENTS data rows is the most we ever accept;
# anything beyond is a hostile/corrupt file and stops the parse immediately.
MAX_FILE_ROWS = MAX_SEGMENTS + 1
MAX_HOSTS = 2 ** 32 - 2


# --------------------------------------------------------------------------
# Segments: export
# --------------------------------------------------------------------------

def export_segments_csv(path: str, rows: Sequence[Tuple[str, int]]) -> None:
    """Write validated (name, hosts) pairs as CSV with a header row."""
    data = io.StringIO()
    writer = csv.writer(data, lineterminator="\r\n")
    writer.writerow(REQ_HEADER)
    for name, hosts in rows:
        writer.writerow([name, hosts])
    atomic_write(path, data.getvalue())


# --------------------------------------------------------------------------
# Segments: import
# --------------------------------------------------------------------------

def load_segments_csv(path: str) -> List[Tuple[str, int]]:
    """Read + validate a segment CSV from disk. Raises PersistenceError."""
    try:
        handle = open(path, "r", encoding="utf-8-sig", newline="")
    except FileNotFoundError:
        raise PersistenceError(f"File not found: '{path}'") from None
    except OSError as exc:
        raise PersistenceError(f"Could not read '{path}': {exc}") from exc

    with handle:
        try:
            return _parse_rows(csv.reader(handle), path)
        except csv.Error as exc:
            raise PersistenceError(f"'{path}': could not parse CSV: {exc}") from exc


def parse_segments_csv(text: str) -> List[Tuple[str, int]]:
    """Pure variant of load_segments_csv for in-memory content."""
    try:
        return _parse_rows(csv.reader(io.StringIO(text)), "CSV content")
    except csv.Error as exc:
        raise PersistenceError(f"Could not parse CSV: {exc}") from exc


def _parse_rows(reader, source: str) -> List[Tuple[str, int]]:
    rows: List[Tuple[str, int]] = []
    first_seen = False
    for lineno, row in enumerate(reader, start=1):
        if not row:  # blank line
            continue
        if lineno > MAX_FILE_ROWS:
            raise PersistenceError(
                f"'{source}': too many rows (max {MAX_SEGMENTS} segments)."
            )
        if len(row) < 2:
            raise PersistenceError(
                f"'{source}' line {lineno}: expected 'name,required_hosts' "
                f"(got {len(row)} column(s))."
            )
        name = (row[0] or "").strip()
        hosts_text = (row[1] or "").strip()

        # Auto-detect and skip a header row: only the FIRST non-blank row may
        # be a header, and only if its hosts column is not an integer.
        if not first_seen:
            first_seen = True
            if not _is_int(hosts_text):
                continue

        if len(rows) >= MAX_SEGMENTS:
            raise PersistenceError(
                f"'{source}': too many segments (max {MAX_SEGMENTS})."
            )

        if not name:
            raise PersistenceError(f"'{source}' line {lineno}: segment name is empty.")
        if len(name) > MAX_NAME_LENGTH:
            raise PersistenceError(
                f"'{source}' line {lineno}: segment name exceeds "
                f"{MAX_NAME_LENGTH} characters."
            )
        if not _is_int(hosts_text):
            raise PersistenceError(
                f"'{source}' line {lineno}: host count '{row[1]}' is not a "
                f"whole number."
            )
        hosts = int(hosts_text)
        if not 1 <= hosts <= MAX_HOSTS:
            raise PersistenceError(
                f"'{source}' line {lineno}: host count {hosts} out of range "
                f"(1..{MAX_HOSTS:,})."
            )
        rows.append((name, hosts))

    if not rows:
        raise PersistenceError(f"'{source}': no segment rows found.")
    return rows


def _is_int(text: str) -> bool:
    try:
        int(text)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Results: export
# --------------------------------------------------------------------------

def export_results_csv(path: str, plan: VlsmPlan) -> None:
    """Write the allocation result table as CSV (analysis-friendly)."""
    data = io.StringIO()
    writer = csv.writer(data, lineterminator="\r\n")
    writer.writerow(RESULT_HEADER)
    for seg in plan.segments:
        writer.writerow(
            [
                seg.name,
                seg.required_hosts,
                f"/{seg.prefix}",
                seg.network,
                netmask_from_prefix(seg.prefix),
                seg.usable_hosts,
                seg.wasted_hosts,
            ]
        )
    atomic_write(path, data.getvalue())