"""Tests for src/persistence/csv_io.py — round-trips, lenient parsing, hostile files."""

import os
import tempfile
import unittest

from src.domain.models import PersistenceError
from src.domain.vlsm import MAX_SEGMENTS, plan_vlsm
from src.persistence.csv_io import (
    export_results_csv,
    export_segments_csv,
    load_segments_csv,
    parse_segments_csv,
)


class TestParseSegmentsCsv(unittest.TestCase):
    def test_with_header(self):
        content = "name,required_hosts\nmgmt,10\nusers,120\n"
        self.assertEqual(parse_segments_csv(content), [("mgmt", 10), ("users", 120)])

    def test_without_header(self):
        content = "mgmt,10\nusers,120\n"
        self.assertEqual(parse_segments_csv(content), [("mgmt", 10), ("users", 120)])

    def test_quoted_name_with_comma(self):
        content = 'name,required_hosts\n"Sales, East",50\n'
        self.assertEqual(parse_segments_csv(content), [("Sales, East", 50)])

    def test_whitespace_and_blank_lines_ignored(self):
        content = "\nname,required_hosts\n  mgmt , 10 \n\nusers,120\n"
        self.assertEqual(parse_segments_csv(content), [("mgmt", 10), ("users", 120)])

    def test_leading_zero_hosts_parsed_as_int(self):
        content = "a,007\n"
        self.assertEqual(parse_segments_csv(content), [("a", 7)])

    def test_empty_content_rejected(self):
        for content in ("", "\n\n", "name,required_hosts\n"):
            with self.subTest(content=repr(content)):
                with self.assertRaises(PersistenceError):
                    parse_segments_csv(content)

    def test_non_numeric_hosts_rejected(self):
        with self.assertRaises(PersistenceError) as ctx:
            parse_segments_csv("name,required_hosts\na,ten\n")
        self.assertIn("line 2", str(ctx.exception))

    def test_out_of_range_hosts_rejected(self):
        for hosts in ("0", "-1", str(2 ** 32 - 1)):
            with self.subTest(hosts=hosts):
                with self.assertRaises(PersistenceError):
                    parse_segments_csv(f"a,{hosts}\n")

    def test_empty_name_rejected(self):
        with self.assertRaises(PersistenceError):
            parse_segments_csv("a,10\n,20\n")

    def test_missing_column_rejected(self):
        with self.assertRaises(PersistenceError):
            parse_segments_csv("a\nb,10\n")

    def test_too_long_name_rejected(self):
        with self.assertRaises(PersistenceError):
            parse_segments_csv(f"{'x' * 65},10\n")

    def test_too_many_rows_rejected(self):
        content = "".join(f"s{i},{i + 1}\n" for i in range(MAX_SEGMENTS + 1))
        with self.assertRaises(PersistenceError):
            parse_segments_csv(content)

    def test_bom_stripped(self):
        content = "\ufeffname,required_hosts\nmgmt,10\n"
        self.assertEqual(parse_segments_csv(content), [("mgmt", 10)])


class TestSegmentsFileRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmpdir.name, name)

    def test_round_trip(self):
        path = self._path("segments.csv")
        rows = [("mgmt", 10), ("Sales, East", 50), ("users", 120)]
        export_segments_csv(path, rows)
        self.assertEqual(load_segments_csv(path), rows)

    def test_missing_file(self):
        with self.assertRaises(PersistenceError):
            load_segments_csv(self._path("nope.csv"))

    def test_export_writes_header(self):
        path = self._path("segments.csv")
        export_segments_csv(path, [("mgmt", 10)])
        with open(path, "r", encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
        self.assertEqual(lines[0], "name,required_hosts")
        self.assertEqual(lines[1], "mgmt,10")


class TestExportResultsCsv(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmpdir.name, name)

    def test_result_rows_and_netmask(self):
        plan = plan_vlsm("192.168.1.0/24", [("users", 120), ("mgmt", 10)])
        path = self._path("results.csv")
        export_results_csv(path, plan)
        with open(path, "r", encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
        self.assertEqual(
            lines[0],
            "segment,required_hosts,prefix,network,netmask,usable_hosts,wasted_hosts",
        )
        # users -> /25, netmask 255.255.255.128
        self.assertEqual(lines[1], "users,120,/25,192.168.1.0,255.255.255.128,126,6")
        self.assertEqual(lines[2], "mgmt,10,/28,192.168.1.128,255.255.255.240,14,4")


if __name__ == "__main__":
    unittest.main()