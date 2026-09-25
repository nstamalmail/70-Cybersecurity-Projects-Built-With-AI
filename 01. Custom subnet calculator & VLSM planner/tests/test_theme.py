"""Tests for src/ui/theme.py — palettes, styling, striping, selection tags.

These are GUI-backed (a hidden Tk root) — they exercise real ttk style
resolution, which is exactly where theming bugs live.
"""

import tkinter as tk
import unittest
from tkinter import ttk

from src.ui import theme


class ThemeTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def test_apply_dark(self):
        tree = ttk.Treeview(self.root, columns=("a",))
        tree.insert("", "end", values=(1,))
        tree.insert("", "end", values=(2,))
        try:
            mode = theme.apply_theme(self.root, "dark", [tree])
            self.assertEqual(mode, "dark")
            style = ttk.Style(self.root)
            self.assertEqual(style.theme_use(), "clam")
            self.assertEqual(style.lookup("TLabel", "background"), theme.DARK["bg"])
            self.assertEqual(style.lookup("TNotebook", "background"), theme.DARK["bg"])
            self.assertEqual(
                style.lookup("Accent.TButton", "background"), theme.DARK["accent"]
            )
            # Even/odd striping tags are applied to existing rows.
            children = tree.get_children()
            self.assertEqual(tree.item(children[0], "tags"), ("even",))
            self.assertEqual(tree.item(children[1], "tags"), ("odd",))
            self.assertEqual(
                str(tree.tag_configure("even", "background")), theme.DARK["tree_even"]
            )
            self.assertEqual(
                str(tree.tag_configure("selected", "background")),
                theme.DARK["selection"],
            )
        finally:
            tree.destroy()

    def test_apply_light_and_invalid_fallback(self):
        mode = theme.apply_theme(self.root, "light")
        self.assertEqual(mode, "light")
        style = ttk.Style(self.root)
        self.assertEqual(style.lookup("TLabel", "background"), theme.LIGHT["bg"])
        # Unknown mode degrades to the default (light).
        mode = theme.apply_theme(self.root, "neon")
        self.assertEqual(mode, "light")

    def test_selection_tag_wins_over_striping(self):
        tree = ttk.Treeview(self.root, columns=("a",))
        try:
            theme.apply_theme(self.root, "dark", [tree])
            tree.insert("", "end", values=(1,))
            tree.insert("", "end", values=(2,))
            item = tree.get_children()[0]
            tree.selection_set(item)
            theme.restripe_tree(tree)
            self.assertEqual(tree.item(item, "tags"), ("selected",))
            self.assertEqual(
                str(tree.tag_configure("selected", "background")),
                theme.DARK["selection"],
            )
            other = tree.get_children()[1]
            self.assertEqual(tree.item(other, "tags"), ("odd",))
        finally:
            tree.destroy()

    def test_restripe_is_idempotent_and_binds_once(self):
        tree = ttk.Treeview(self.root, columns=("a",))
        try:
            theme.apply_theme(self.root, "dark", [tree])
            tree.insert("", "end", values=(1,))
            theme.restripe_tree(tree)
            theme.restripe_tree(tree)
            self.assertTrue(getattr(tree, "_stripe_bound", False))
            self.assertEqual(tree.item(tree.get_children()[0], "tags"), ("even",))
        finally:
            tree.destroy()

    def test_toggle_between_palettes(self):
        tree = ttk.Treeview(self.root, columns=("a",))
        tree.insert("", "end", values=(1,))
        try:
            theme.apply_theme(self.root, "dark", [tree])
            theme.apply_theme(self.root, "light", [tree])
            style = ttk.Style(self.root)
            self.assertEqual(style.lookup("TLabel", "background"), theme.LIGHT["bg"])
            self.assertEqual(
                str(tree.tag_configure("even", "background")), theme.LIGHT["tree_even"]
            )
        finally:
            tree.destroy()


if __name__ == "__main__":
    unittest.main()