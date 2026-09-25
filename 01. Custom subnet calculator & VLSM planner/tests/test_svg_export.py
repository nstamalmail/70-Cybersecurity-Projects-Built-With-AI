"""Tests for src/persistence/svg_export.py — geometry, escaping, output shape."""

import os
import tempfile
import unittest

from src.domain.models import VlsmPlan, VlsmSegment
from src.domain.vlsm import plan_vlsm
from src.persistence.svg_export import _layout, export_svg, render_vlsm_svg

LEFT, RIGHT = 60, 980  # canvas geometry constants mirrored from the module


class TestLayout(unittest.TestCase):
    def test_widths_proportional_to_block_sizes(self):
        plan = plan_vlsm(
            "192.168.1.0/24", [("A", 100), ("B", 50), ("C", 25), ("D", 10)]
        )
        blocks, total_size, prefix = _layout(plan)
        self.assertEqual(total_size, 256)
        self.assertEqual(prefix, 24)
        segs = [b for b in blocks if b["kind"] == "seg"]
        # /25:/26:/27:/28 sizes 128:64:32:16 -> widths 460:230:115:57.5
        self.assertAlmostEqual(segs[0]["width"], 460.0, places=1)
        self.assertAlmostEqual(segs[1]["width"], 230.0, places=1)
        self.assertAlmostEqual(segs[2]["width"], 115.0, places=1)
        self.assertAlmostEqual(segs[3]["width"], 57.5, places=1)

    def test_contiguous_allocation_leaves_tail_gap(self):
        plan = plan_vlsm("192.168.1.0/24", [("A", 100)])
        blocks, _, _ = _layout(plan)
        self.assertEqual(blocks[0]["kind"], "seg")
        self.assertEqual(blocks[1]["kind"], "gap")
        self.assertAlmostEqual(blocks[0]["width"], 460.0, places=1)
        self.assertAlmostEqual(blocks[1]["width"], 460.0, places=1)  # /25 + tail

    def test_crafted_non_contiguous_plan_renders_gap_between_segments(self):
        plan = VlsmPlan(
            base_network="192.168.1.0/24",
            segments=(
                VlsmSegment("a", 10, 26, "192.168.1.0", 62, 52),
                VlsmSegment("b", 10, 26, "192.168.1.192", 62, 52),
            ),
        )
        blocks, _, _ = _layout(plan)
        kinds = [b["kind"] for b in blocks]
        self.assertEqual(kinds, ["seg", "gap", "seg"])
        self.assertAlmostEqual(blocks[1]["width"], 460.0, places=1)  # 128 addresses

    def test_crowded_plan_never_overlaps(self):
        # 300 x /32 needs a /23 base (512 addresses); octets stay in range.
        segments = tuple(
            VlsmSegment(f"s{i}", 1, 32, f"10.0.{i // 256}.{i % 256}", 1, 0)
            for i in range(300)
        )
        plan = VlsmPlan(base_network="10.0.0.0/23", segments=segments)
        blocks, _, _ = _layout(plan)
        segs = [b for b in blocks if b["kind"] == "seg"]
        self.assertEqual(len(segs), 300)
        # No block may start left of the previous block's right edge.
        prev_right = 0.0
        for b in segs:
            self.assertGreaterEqual(b["x"], prev_right - 0.01)
            prev_right = b["x"] + b["width"]

    def test_empty_plan_single_full_gap(self):
        plan = VlsmPlan(base_network="10.0.0.0/8")
        blocks, total_size, _ = _layout(plan)
        self.assertEqual(total_size, 2 ** 24)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["kind"], "gap")
        self.assertAlmostEqual(blocks[0]["width"], RIGHT - LEFT, places=3)


class TestRender(unittest.TestCase):
    def test_output_shape(self):
        plan = plan_vlsm("192.168.1.0/24", [("A", 100), ("B", 50)])
        svg = render_vlsm_svg(plan)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.strip().endswith("</svg>"))
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', svg)

    def test_contains_plan_details(self):
        plan = plan_vlsm("192.168.1.0/24", [("users", 120), ("mgmt", 10)])
        svg = render_vlsm_svg(plan)
        self.assertIn("192.168.1.0/24", svg)
        self.assertIn("users", svg)
        self.assertIn("mgmt", svg)
        self.assertIn("efficiency", svg)

    def test_names_are_xml_escaped(self):
        plan = plan_vlsm("10.0.0.0/24", [("Sales & Ops <HQ>", 10)])
        svg = render_vlsm_svg(plan)
        self.assertIn("Sales &amp; Ops &lt;HQ&gt;", svg)
        self.assertNotIn("Sales & Ops <HQ>", svg)

    def test_waste_overlay_present(self):
        plan = plan_vlsm("192.168.1.0/24", [("A", 100)])  # /25, 26 wasted
        svg = render_vlsm_svg(plan)
        self.assertIn('id="waste"', svg)
        # Overlay rect + legend swatch -> at least two references.
        self.assertGreaterEqual(svg.count("url(#waste)"), 2)

    def test_zero_waste_means_legend_reference_only(self):
        plan = plan_vlsm("10.0.0.0/29", [("p2p", 2)])  # /31, wasted 0
        svg = render_vlsm_svg(plan)
        # The pattern is defined and the legend swatch uses it, but no block
        # overlay is drawn -> exactly one reference.
        self.assertEqual(svg.count("url(#waste)"), 1)

    def test_empty_plan_message(self):
        plan = VlsmPlan(base_network="10.0.0.0/8")
        svg = render_vlsm_svg(plan)
        self.assertIn("No segments allocated", svg)


class TestExportFile(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def test_export_writes_svg(self):
        plan = plan_vlsm("192.168.1.0/24", [("A", 100)])
        path = os.path.join(self.tmpdir.name, "plan.svg")
        export_svg(path, plan)
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertTrue(content.startswith("<svg"))
        self.assertIn("VLSM Allocation", content)


if __name__ == "__main__":
    unittest.main()