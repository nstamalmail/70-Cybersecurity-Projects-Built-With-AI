"""Tests for src/persistence/repository.py — round-trips and hostile files."""

import json
import os
import tempfile
import unittest

from src.domain.models import PersistenceError
from src.domain.vlsm import plan_vlsm
from src.persistence.repository import export_report, load_plan, save_plan


class TestRepository(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmpdir.name, name)

    def _sample_plan(self):
        return plan_vlsm(
            "192.168.1.0/24",
            [("mgmt", 10), ("users", 120), ("guest", 30)],
        )

    def test_round_trip(self):
        path = self._path("plan.json")
        plan = self._sample_plan()
        save_plan(path, plan)
        loaded = load_plan(path)
        self.assertEqual(loaded.base_network, plan.base_network)
        self.assertEqual(
            [(s.name, s.required_hosts, s.prefix, s.network) for s in loaded.segments],
            [(s.name, s.required_hosts, s.prefix, s.network) for s in plan.segments],
        )
        self.assertEqual(loaded.total_required, plan.total_required)
        self.assertEqual(loaded.total_wasted, plan.total_wasted)
        self.assertAlmostEqual(loaded.efficiency, plan.efficiency, places=6)

    def test_file_is_plain_json(self):
        path = self._path("plan.json")
        save_plan(path, self._sample_plan())
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["format"], "vlsm-plan")
        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("segments", payload)

    def test_missing_file(self):
        with self.assertRaises(PersistenceError):
            load_plan(self._path("nope.json"))

    def test_invalid_json(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ not json !!")
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_wrong_format_tag(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"format": "other", "schema_version": 1}, handle)
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_wrong_schema_version(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"format": "vlsm-plan", "schema_version": 99, "base_network": "10.0.0.0/24", "segments": []}, handle)
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_segments_not_a_list(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"format": "vlsm-plan", "schema_version": 1,
                       "base_network": "10.0.0.0/24", "segments": "oops"}, handle)
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_empty_segment_list_rejected(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"format": "vlsm-plan", "schema_version": 1,
                       "base_network": "10.0.0.0/24", "segments": []}, handle)
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_hand_edited_derived_fields_are_recomputed(self):
        """Stored derived fields are ignored; the allocator re-derives truth."""
        path = self._path("crafted.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "format": "vlsm-plan",
                    "schema_version": 1,
                    "base_network": "192.168.1.0/24",
                    "segments": [
                        {
                            "name": "users",
                            "required_hosts": 120,
                            # malicious /23 claim — must be ignored/recomputed
                            "prefix": 23,
                            "network": "10.0.0.0",
                            "usable_hosts": 999999,
                            "wasted_hosts": 0,
                        }
                    ],
                },
                handle,
            )
        loaded = load_plan(path)
        self.assertEqual(loaded.segments[0].prefix, 25)
        self.assertEqual(loaded.segments[0].usable_hosts, 126)
        self.assertEqual(loaded.segments[0].network, "192.168.1.0")

    def test_inconsistent_plan_rejected(self):
        """A file whose required_hosts cannot fit the base network is rejected."""
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "format": "vlsm-plan",
                    "schema_version": 1,
                    "base_network": "192.168.1.0/24",
                    "segments": [{"name": "big", "required_hosts": 300}],
                },
                handle,
            )
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_hosts_out_of_range_rejected(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "format": "vlsm-plan",
                    "schema_version": 1,
                    "base_network": "10.0.0.0/8",
                    "segments": [{"name": "big", "required_hosts": 2 ** 40}],
                },
                handle,
            )
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_bool_hosts_rejected(self):
        path = self._path("bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "format": "vlsm-plan",
                    "schema_version": 1,
                    "base_network": "10.0.0.0/8",
                    "segments": [{"name": "a", "required_hosts": True}],
                },
                handle,
            )
        with self.assertRaises(PersistenceError):
            load_plan(path)

    def test_export_report(self):
        path = self._path("report.txt")
        export_report(path, self._sample_plan())
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("VLSM PLAN REPORT", content)
        self.assertIn("192.168.1.0/24", content)
        self.assertIn("users", content)
        self.assertIn("Allocation efficiency", content)


if __name__ == "__main__":
    unittest.main()