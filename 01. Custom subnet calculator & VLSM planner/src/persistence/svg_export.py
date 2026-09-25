"""SVG export: a visual address-space map of a VLSM plan.

The diagram is a single horizontal bar spanning the base network. Each
allocated segment is a rectangle whose width is proportional to its address
block; unused capacity inside a block (wasted hosts) is hatched; address
space not allocated to any segment is shown as a light gap. Every block is
labelled with its network, prefix and host counts, and a legend + totals are
rendered at the bottom.

The output is fully self-contained (inline styles, no external references),
so it opens in any browser, viewer or image converter.

Security: names are XML-escaped; data only, no dynamic code.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List
from xml.sax.saxutils import escape

from ..domain.models import VlsmPlan
from ..domain.vlsm import ip_int_to_str
from .repository import atomic_write

# Canvas geometry (viewBox units).
WIDTH, HEIGHT = 1000, 360
LEFT, RIGHT = 60, 980          # bar spans x in [LEFT, RIGHT]
TOP = 115                      # top of the block row
BLOCK_H = 80                   # block row height
MIN_BLOCK_W = 20.0             # smallest rendered block (may shrink if crowded)

FONT = "Segoe UI, Arial, sans-serif"
INK = "#333333"
MUTED = "#888888"

# Categorical palette, cycled per segment.
PALETTE = [
    "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
    "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
]


def render_vlsm_svg(plan: VlsmPlan) -> str:
    """Render the plan as a self-contained SVG document (pure function)."""
    blocks, total_size, base_prefix = _layout(plan)
    n = len(plan.segments)

    parts: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" font-family="{FONT}">',
        "<defs>",
        # Hatch used to mark wasted capacity inside allocated blocks.
        '<pattern id="waste" width="6" height="6" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)">'
        '<rect width="6" height="6" fill="rgba(0,0,0,0.10)"/>'
        '<line x1="0" y1="0" x2="0" y2="6" stroke="rgba(0,0,0,0.30)" stroke-width="2"/>'
        "</pattern>",
        "</defs>",
    ]

    # Title + subtitle.
    parts.append(
        f'<text x="{LEFT}" y="40" font-size="20" font-weight="bold" fill="{INK}">'
        f"VLSM Allocation — {escape(plan.base_network)}</text>"
    )
    parts.append(
        f'<text x="{LEFT}" y="62" font-size="13" fill="{MUTED}">'
        f"{total_size:,} addresses in the base network · {n} segment"
        f"{'s' if n != 1 else ''} · usable counts follow RFC 3021</text>"
    )

    # Bar background (unallocated address space).
    parts.append(
        f'<rect x="{LEFT}" y="{TOP}" width="{RIGHT - LEFT}" height="{BLOCK_H}" '
        'fill="#f2f2f2" stroke="#cccccc" stroke-width="1"/>'
    )

    for block in blocks:
        x = round(block["x"], 2)
        w = round(block["width"], 2)
        if block["kind"] == "gap":
            if w >= 2:
                parts.append(
                    f'<rect x="{x}" y="{TOP}" width="{w}" height="{BLOCK_H}" '
                    'fill="#f7f7f7" stroke="#dddddd" stroke-dasharray="4,3"/>'
                )
            continue

        seg = block["seg"]
        color = PALETTE[block["index"] % len(PALETTE)]
        parts.append(
            f'<rect x="{x}" y="{TOP}" width="{w}" height="{BLOCK_H}" '
            f'fill="{color}" stroke="#ffffff" stroke-width="1.5" rx="2"/>'
        )

        # Wasted capacity overlay: right end of the block, hatched.
        waste_frac = seg.wasted_hosts / block["size"] if block["size"] else 0.0
        if 0 < waste_frac < 0.999 and w >= 12:
            waste_w = max(w * waste_frac, 4.0)
            parts.append(
                f'<rect x="{round(x + w - waste_w, 2)}" y="{TOP}" '
                f'width="{round(waste_w, 2)}" height="{BLOCK_H}" '
                'fill="url(#waste)"/>'
            )

        # Inside-block labels (only when there is room).
        if w >= 72:
            cx = x + 8
            parts.append(
                f'<text x="{cx}" y="{TOP + 20}" font-size="12" font-weight="bold" '
                f'fill="#ffffff">{escape(seg.name)}</text>'
            )
            parts.append(
                f'<text x="{cx}" y="{TOP + 38}" font-size="11" fill="#ffffff">'
                f"{escape(seg.network)}/{seg.prefix}</text>"
            )
            parts.append(
                f'<text x="{cx}" y="{TOP + 54}" font-size="10" fill="#ffffff" '
                f'opacity="0.9">usable {seg.usable_hosts:,} · '
                f"wasted {seg.wasted_hosts:,}</text>"
            )

        # Below-block labels, centred on the block. The full address range
        # needs wide blocks; narrow ones keep just the name so neighbours
        # never overlap.
        end = block["offset"] + block["size"] - 1
        if w >= 40:
            parts.append(
                f'<text x="{round(x + w / 2, 2)}" y="{TOP + BLOCK_H + 16}" '
                f'font-size="10.5" font-weight="bold" fill="{INK}" '
                f'text-anchor="middle">{escape(seg.name)}</text>'
            )
        if w >= 100:
            parts.append(
                f'<text x="{round(x + w / 2, 2)}" y="{TOP + BLOCK_H + 30}" '
                f'font-size="9.5" fill="{MUTED}" text-anchor="middle">'
                f"{escape(seg.network)}/{seg.prefix} → {escape(ip_int_to_str(end))}"
                "</text>"
            )

    # Legend.
    legend_y = 280
    parts.append(_legend_item(legend_y, LEFT, 24, PALETTE[0], "Allocated segment"))
    parts.append(_legend_item(legend_y, LEFT + 210, 24, "url(#waste)", "Wasted capacity (unused hosts in a block)"))
    parts.append(
        f'<rect x="{LEFT + 490}" y="{legend_y - 14}" width="24" height="16" '
        'fill="#f2f2f2" stroke="#cccccc"/>'
    )
    parts.append(
        f'<text x="{LEFT + 520}" y="{legend_y}" font-size="11" fill="{INK}">'
        "Unallocated address space</text>"
    )

    # Footer stats.
    if n:
        stats = (
            f"Total required {plan.total_required:,} · addresses allocated "
            f"{plan.total_allocated:,} · hosts wasted {plan.total_wasted:,} · "
            f"efficiency {plan.efficiency * 100:.2f}%"
        )
    else:
        stats = "No segments allocated — the base network is fully unallocated."
    parts.append(
        f'<text x="{LEFT}" y="332" font-size="12" font-weight="bold" fill="{INK}">'
        f"{escape(stats)}</text>"
    )

    parts.append("</svg>")
    return "\n".join(parts)


def _legend_item(text_y: int, x: int, size: int, fill: str, label: str) -> str:
    return (
        f'<rect x="{x}" y="{text_y - 14}" width="{size}" height="16" fill="{fill}" '
        f'stroke="#cccccc"/><text x="{x + size + 8}" y="{text_y}" font-size="11" '
        f'fill="{INK}">{escape(label)}</text>'
    )


def _layout(plan: VlsmPlan) -> tuple[List[Dict], int, int]:
    """Compute block geometry: (blocks, total_size, base_prefix).

    Blocks are segment rects and gap rects, in x-order, with x/width in
    canvas units. Segment blocks carry their segment plus offset/size in
    address units.
    """
    base = ipaddress.IPv4Network(plan.base_network, strict=False)
    base_prefix = base.prefixlen
    total_size = 2 ** (32 - base_prefix)
    base_start = int(base.network_address)
    avail = RIGHT - LEFT
    scale = avail / total_size

    # Avoid overlap when blocks are tiny: a forced width must never exceed
    # the tightest spacing between adjacent blocks, which is the smallest
    # allocated block size scaled to canvas units.
    smallest_size = min((2 ** (32 - seg.prefix) for seg in plan.segments), default=0)
    min_w = min(MIN_BLOCK_W, scale * smallest_size) if smallest_size else MIN_BLOCK_W

    blocks: List[Dict] = []
    prev_end = 0
    for index, seg in enumerate(plan.segments):
        start = int(ipaddress.IPv4Address(seg.network))
        offset = start - base_start
        size = 2 ** (32 - seg.prefix)
        if offset > prev_end:
            blocks.append(
                {
                    "kind": "gap",
                    "x": LEFT + prev_end * scale,
                    "width": (offset - prev_end) * scale,
                }
            )
        x = LEFT + offset * scale
        width = max(size * scale, min_w)
        if x + width > RIGHT:
            width = RIGHT - x
        blocks.append(
            {
                "kind": "seg",
                "seg": seg,
                "index": index,
                "x": x,
                "width": width,
                "offset": offset,
                "size": size,
            }
        )
        prev_end = offset + size

    if prev_end < total_size:
        blocks.append(
            {
                "kind": "gap",
                "x": LEFT + prev_end * scale,
                "width": (total_size - prev_end) * scale,
            }
        )
    return blocks, total_size, base_prefix


def export_svg(path: str, plan: VlsmPlan) -> None:
    """Render the plan to an SVG file (atomic write)."""
    atomic_write(path, render_vlsm_svg(plan))