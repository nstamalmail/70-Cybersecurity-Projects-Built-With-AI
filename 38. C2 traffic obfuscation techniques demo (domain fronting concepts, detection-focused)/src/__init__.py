"""C2 Detection Workbench — synthetic, offline, detection-focused.

Safety contract (see architecture.md §0):
- No network I/O of any kind (enforced by src/safety.py via static AST scan).
- Only RFC 5737 / RFC 3849 documentation IPs and reserved-TLD domains.
- Everything is fabricated from seeded scenarios; nothing is captured live.
"""

__version__ = "1.0.0"
