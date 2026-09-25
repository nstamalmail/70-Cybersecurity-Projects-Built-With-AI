"""Tests for src/persistence/config.py — defaults, round-trips, hostile files."""

import json
import os
import tempfile
import unittest
from unittest import mock

from src.persistence import config


class TestConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        patcher = mock.patch.object(
            config, "_path", return_value=os.path.join(self.tmpdir.name, "config.json")
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, data: dict) -> None:
        with open(config._path(), "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def test_default_theme_without_file(self):
        self.assertEqual(config.load_theme(), "light")

    def test_round_trip(self):
        config.save_theme("dark")
        self.assertEqual(config.load_theme(), "dark")

    def test_file_content(self):
        config.save_theme("dark")
        with open(config._path(), "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {"theme": "dark"})

    def test_invalid_theme_falls_back_to_default(self):
        self._write({"theme": "purple"})
        self.assertEqual(config.load_theme(), "light")

    def test_corrupt_file_degrades_gracefully(self):
        with open(config._path(), "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        self.assertEqual(config.load_config(), {})
        self.assertEqual(config.load_theme(), "light")

    def test_non_dict_config_ignored(self):
        with open(config._path(), "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        self.assertEqual(config.load_config(), {})

    def test_save_theme_normalizes_invalid(self):
        config.save_theme("neon")
        self.assertEqual(config.load_theme(), "light")

    def test_save_preserves_other_keys(self):
        self._write({"window_width": 1080})
        config.save_theme("dark")
        cfg = config.load_config()
        self.assertEqual(cfg["theme"], "dark")
        self.assertEqual(cfg["window_width"], 1080)


if __name__ == "__main__":
    unittest.main()