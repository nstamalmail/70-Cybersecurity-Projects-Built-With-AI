"""Tests for src/domain/vlsm.py — textbook vectors, ordering, overflow, caps."""

import unittest

from src.domain.models import PlannerError
from src.domain.vlsm import MAX_SEGMENTS, plan_vlsm, segments_from_rows


class TestPlanVlsm(unittest.TestCase):
    def test_textbook_example(self):
        """192.168.1.0/24 with 100/50/25/10 hosts — classic VLSM."""
        plan = plan_vlsm(
            "192.168.1.0/24",
            [("A", 100), ("B", 50), ("C", 25), ("D", 10)],
        )
        self.assertEqual(
            [(s.name, s.prefix, s.network) for s in plan.segments],
            [
                ("A", 25, "192.168.1.0"),
                ("B", 26, "192.168.1.128"),
                ("C", 27, "192.168.1.192"),
                ("D", 28, "192.168.1.224"),
            ],
        )
        self.assertEqual([s.usable_hosts for s in plan.segments],
                         [126, 62, 30, 14])
        self.assertEqual([s.wasted_hosts for s in plan.segments], [26, 12, 5, 4])
        self.assertEqual(plan.total_required, 185)
        self.assertEqual(plan.total_allocated, 240)
        self.assertEqual(plan.total_wasted, 47)  # 26 + 12 + 5 + 4
        self.assertAlmostEqual(plan.efficiency, 185 / 240, places=6)

    def test_segments_without_overhead(self):
        """Segments that exactly fill a block have zero waste."""
        plan = plan_vlsm("10.0.0.0/24", [("a", 126), ("b", 62), ("c", 30), ("d", 14)])
        # Every block is exactly used: usable == required, so wasted == 0.
        # Efficiency is still < 1 because network/broadcast addresses are
        # part of the allocated size but not usable.
        self.assertEqual([s.wasted_hosts for s in plan.segments], [0, 0, 0, 0])
        self.assertAlmostEqual(plan.efficiency, 232 / 240, places=6)

    def test_stable_order_for_equal_demand(self):
        plan = plan_vlsm(
            "10.0.0.0/24",
            [("first", 30), ("second", 30), ("third", 30)],
        )
        self.assertEqual([s.name for s in plan.segments],
                         ["first", "second", "third"])

    def test_rfc3021_small_segments(self):
        plan = plan_vlsm("10.0.0.0/29", [("p2p", 2), ("host", 1)])
        # 2 hosts -> /31 (2 usable), 1 host -> /32 (1 usable)
        self.assertEqual([s.prefix for s in plan.segments], [31, 32])
        self.assertEqual(plan.total_allocated, 3)  # 2 + 1 addresses

    def test_segment_larger_than_base_rejected(self):
        with self.assertRaises(PlannerError) as ctx:
            plan_vlsm("10.0.0.0/24", [("big", 300)])
        self.assertIn("larger than the base network", str(ctx.exception))

    def test_cumulative_overflow_rejected(self):
        with self.assertRaises(PlannerError) as ctx:
            plan_vlsm(
                "10.0.0.0/24",
                [("a", 120), ("b", 120), ("c", 120)],
            )
        self.assertIn("exceeds base network", str(ctx.exception))

    def test_exact_fit_at_boundary(self):
        plan = plan_vlsm(
            "10.0.0.0/24",
            [("a", 126), ("b", 126)],
        )
        self.assertEqual([s.network for s in plan.segments],
                         ["10.0.0.0", "10.0.0.128"])

    def test_empty_segments_rejected(self):
        with self.assertRaises(PlannerError):
            plan_vlsm("10.0.0.0/24", [])

    def test_blank_name_rejected(self):
        with self.assertRaises(PlannerError):
            plan_vlsm("10.0.0.0/24", [("   ", 10)])

    def test_long_name_rejected(self):
        with self.assertRaises(PlannerError):
            plan_vlsm("10.0.0.0/24", [("x" * 65, 10)])

    def test_bad_host_counts_rejected(self):
        for hosts in (0, -5, 2 ** 32 - 1):
            with self.subTest(hosts=hosts):
                with self.assertRaises(PlannerError):
                    plan_vlsm("10.0.0.0/24", [("a", hosts)])

    def test_too_many_segments_rejected(self):
        rows = [(f"seg{i}", 1) for i in range(MAX_SEGMENTS + 1)]
        with self.assertRaises(PlannerError):
            plan_vlsm("10.0.0.0/8", rows)

    def test_invalid_base_rejected(self):
        with self.assertRaises(PlannerError):
            plan_vlsm("banana", [("a", 10)])

    def test_small_base_with_host_bits(self):
        plan = plan_vlsm("192.168.1.37/24", [("a", 10)])
        self.assertEqual(plan.base_network, "192.168.1.0/24")


class TestSegmentsFromRows(unittest.TestCase):
    def test_converts(self):
        rows = [("mgmt", "10"), ("users", " 120 ")]
        self.assertEqual(segments_from_rows(rows), [("mgmt", 10), ("users", 120)])

    def test_commas_stripped_by_caller_not_here(self):
        with self.assertRaises(PlannerError):
            segments_from_rows([("mgmt", "1,000")])

    def test_non_numeric_rejected_with_row_hint(self):
        with self.assertRaises(PlannerError) as ctx:
            segments_from_rows([("a", "ten"), ("b", "5")])
        self.assertIn("Row 1", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()