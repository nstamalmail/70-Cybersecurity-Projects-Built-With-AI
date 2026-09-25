"""Headless core of the ARP scanner.

This package must never import from ``ui`` — it is usable from the CLI,
tests, and any future front-end. All Windows API calls live here and
nowhere else (see architecture.md §2, layer rules).
"""

__all__ = ["engine", "exporter", "interface", "models", "oui"]
__version__ = "1.0.0"
