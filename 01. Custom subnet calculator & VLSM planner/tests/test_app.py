"""Tests for src/app.py — controller facade, UserError mapping, message quality."""

import os
import tempfile
import unittest
from unittest import mock

from src.app import AppController, UserError
from src.domain.models import SubnetInfo, VlsmPlan
from src.persistence import config


class TestAppController(unittest.TestCase):
    def setUp(self) -> None:
        self.app = AppController()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        # Never touch the real per-user config during tests.
        patcher = mock.patch.object(
            config, "_path", return_value=os.path.join(self.tmpdir.name, "config.json")
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmpdir.name, name)

    def test_calculate_ok(self):
        info = self.app.calculate("192.168.1.25", "24")
        self.assertIsInstance(info, SubnetInfo)
        self.assertEqual(info.network, "192.168.1.0/24")

    def test_calculate_bad_ip_maps_to_user_error(self):
        with self.assertRaises(UserError) as ctx:
            self.app.calculate("999.1.1.1", "24")
        self.assertIn("not a valid IPv4", str(ctx.exception))

    def test_calculate_bad_prefix_maps_to_user_error(self):
        with self.assertRaises(UserError):
            self.app.calculate("10.0.0.1", "33")

    def test_plan_ok_and_summary(self):
        plan = self.app.plan("192.168.1.0/24", [("a", "10"), ("b", "120")])
        self.assertIsInstance(plan, VlsmPlan)
        summary = self.app.summary(plan)
        self.assertIn("efficiency", summary)
        self.assertEqual(summary["total_required"], 130)

    def test_plan_overflow_maps_to_user_error(self):
        with self.assertRaises(UserError) as ctx:
            self.app.plan("10.0.0.0/24", [("big", "300")])
        self.assertIn("base network", str(ctx.exception))

    def test_plan_bad_row_maps_to_user_error(self):
        with self.assertRaises(UserError) as ctx:
            self.app.plan("10.0.0.0/24", [("a", "ten")])
        self.assertIn("Row 1", str(ctx.exception))

    def test_save_load_round_trip(self):
        plan = self.app.plan("10.0.0.0/24", [("a", "10")])
        path = self._path("plan.json")
        self.app.save_plan(path, plan)
        loaded = self.app.load_plan(path)
        self.assertEqual(loaded.base_network, plan.base_network)

    def test_load_missing_file_maps_to_user_error(self):
        with self.assertRaises(UserError) as ctx:
            self.app.load_plan(self._path("missing.json"))
        self.assertIn("File not found", str(ctx.exception))

    def test_export_report(self):
        plan = self.app.plan("10.0.0.0/24", [("a", "10")])
        path = self._path("report.txt")
        self.app.export_report(path, plan)
        self.assertTrue(os.path.exists(path))

    def test_import_segments_ok_and_bad_file(self):
        path = self._path("segments.csv")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("name,required_hosts\nmgmt,10\n")
        self.assertEqual(self.app.import_segments(path), [("mgmt", 10)])

        with self.assertRaises(UserError):
            self.app.import_segments(self._path("nope.csv"))

    def test_export_segments_validates_rows(self):
        with self.assertRaises(UserError) as ctx:
            self.app.export_segments(self._path("out.csv"), [("a", "ten")])
        self.assertIn("Row 1", str(ctx.exception))

    def test_export_results_csv(self):
        plan = self.app.plan("10.0.0.0/24", [("a", "10")])
        path = self._path("results.csv")
        self.app.export_results_csv(path, plan)
        self.assertTrue(os.path.exists(path))

    def test_theme_default_is_light(self):
        self.assertEqual(self.app.get_theme(), "light")

    def test_theme_round_trip(self):
        self.assertEqual(self.app.set_theme("dark"), "dark")
        self.assertEqual(self.app.get_theme(), "dark")

    def test_theme_invalid_normalized(self):
        self.assertEqual(self.app.set_theme("neon"), "light")
        self.assertEqual(self.app.get_theme(), "light")


if __name__ == "__main__":
    unittest.main()