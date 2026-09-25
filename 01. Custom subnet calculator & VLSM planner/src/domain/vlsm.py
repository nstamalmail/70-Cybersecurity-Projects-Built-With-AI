"""VLSM (Variable Length Subnet Masking) planner — pure allocation logic.

Algorithm (classic textbook VLSM):
  1. Sort segments by required host count, descending (stable — ties keep
     input order).
  2. For each segment, allocate the smallest CIDR block whose usable host
     count satisfies the requirement.
  3. Place blocks contiguously, starting at the base network address.
  4. Reject the plan if any block would exceed the base network's broadcast
     address (the base network is too small for the total demand).
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from .calculator import network_from_string, usable_host_count
from .models import PlannerError, VlsmPlan, VlsmSegment

MAX_SEGMENTS = 500
MAX_HOSTS_PER_SEGMENT = 2 ** 32 - 2
MAX_NAME_LENGTH = 64


def plan_vlsm(base_network_text: str, segments: Sequence[Tuple[str, int]]) -> VlsmPlan:
    """Allocate a contiguous VLSM plan.

    Args:
        base_network_text: "a.b.c.d/prefix" — the address space to carve up.
        segments: ordered list of (name, required_hosts). Order is preserved
            for segments with equal host requirements.

    Raises:
        PlannerError: on invalid inputs or if demand exceeds the base network.
    """
    base = network_from_string(base_network_text)

    if not segments:
        raise PlannerError("Add at least one segment before planning.")
    if len(segments) > MAX_SEGMENTS:
        raise PlannerError(f"Too many segments (max {MAX_SEGMENTS}).")

    validated: List[Tuple[str, int]] = []
    for name, required in segments:
        clean_name = (name or "").strip()
        if not clean_name:
            raise PlannerError("Every segment needs a name.")
        if len(clean_name) > MAX_NAME_LENGTH:
            raise PlannerError(
                f"Segment name '{clean_name[:20]}…' exceeds {MAX_NAME_LENGTH} characters."
            )
        if isinstance(required, bool) or not isinstance(required, int):
            raise PlannerError(f"Host count for '{clean_name}' must be a whole number.")
        if not 1 <= required <= MAX_HOSTS_PER_SEGMENT:
            raise PlannerError(
                f"Host count for '{clean_name}' must be between 1 and "
                f"{MAX_HOSTS_PER_SEGMENT:,}."
            )
        validated.append((clean_name, required))

    # Stable descending sort: segments with equal demand keep input order.
    ordered = sorted(validated, key=lambda item: item[1], reverse=True)

    cursor = int(base.network_address)
    base_broadcast = int(base.broadcast_address)
    allocated: List[VlsmSegment] = []
    total_allocated = 0

    for name, required in ordered:
        prefix = _smallest_prefix_for(required, base.prefixlen)
        if prefix < base.prefixlen:
            raise PlannerError(
                f"Segment '{name}' needs {required} hosts, which requires a block "
                f"larger than the base network {base}."
            )
        block_size = 2 ** (32 - prefix)
        if cursor + block_size - 1 > base_broadcast:
            raise PlannerError(
                f"Total demand exceeds base network {base}: segment '{name}' "
                f"({required} hosts) does not fit after the previously allocated "
                f"blocks. Enlarge the base network or reduce segment sizes."
            )
        capacity = usable_host_count(prefix)
        allocated.append(
            VlsmSegment(
                name=name,
                required_hosts=required,
                prefix=prefix,
                network=str(ip_int_to_str(cursor)),
                usable_hosts=capacity,
                wasted_hosts=capacity - required,
            )
        )
        total_allocated += block_size
        cursor += block_size

    total_required = sum(seg.required_hosts for seg in allocated)
    total_wasted = sum(seg.wasted_hosts for seg in allocated)
    efficiency = total_required / total_allocated if total_allocated else 0.0

    return VlsmPlan(
        base_network=str(base),
        segments=tuple(allocated),
        total_required=total_required,
        total_allocated=total_allocated,
        total_wasted=total_wasted,
        efficiency=efficiency,
    )


def _smallest_prefix_for(required_hosts: int, floor_prefix: int) -> int:
    """Smallest prefix p (>= floor_prefix) whose usable capacity fits demand.

    Iterates from /32 (smallest block) down to floor_prefix. Returns
    floor_prefix - 1 when even the base-sized block is too small, signalling
    that the segment does not fit the base network.
    """
    for prefix in range(32, floor_prefix - 1, -1):
        if usable_host_count(prefix) >= required_hosts:
            return prefix
    return floor_prefix - 1


def ip_int_to_str(value: int) -> str:
    """Render an integer IPv4 address as dotted-quad."""
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def segments_from_rows(rows: Iterable[Tuple[str, str]]) -> List[Tuple[str, int]]:
    """Convert raw GUI rows [(name, hosts_as_str)] into validated pairs.

    Raises PlannerError on malformed host counts so the UI can show one
    message covering the offending row.
    """
    result: List[Tuple[str, int]] = []
    for idx, (name, hosts_text) in enumerate(rows, start=1):
        clean_name = (name or "").strip()
        try:
            hosts = int(str(hosts_text).strip())
        except (TypeError, ValueError):
            raise PlannerError(
                f"Row {idx} ('{clean_name or 'unnamed'}'): host count "
                f"'{hosts_text}' is not a whole number."
            ) from None
        result.append((clean_name, hosts))
    return result