"""Wordlist provider: builtin educational lists + user-selected external files.

Encoding policy: UTF-8 with errors='replace', BOM stripped, lines > 256 chars
dropped (defensive), duplicates removed preserving first occurrence order.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional, Tuple

MAX_LINE = 256


def _resource_root() -> str:
    """Directory holding bundled assets, PyInstaller-aware."""
    base = getattr(sys, "_MEIPASS", None)  # PyInstaller onefile extraction dir
    if base and os.path.isdir(os.path.join(base, "assets", "wordlists")):
        return os.path.join(base, "assets")
    # Source layout: <root>/assets/wordlists ; this file lives at <root>/core/
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    return os.path.join(root, "assets")


def builtin_wordlists() -> List[Tuple[str, str]]:
    """(label, absolute_path) for every builtin list found."""
    d = os.path.join(_resource_root(), "wordlists")
    out = []
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if fn.lower().endswith(".txt"):
                p = os.path.join(d, fn)
                if os.path.isfile(p):
                    out.append((fn, p))
    return out


def load_wordlist(path: str) -> List[str]:
    """Load a wordlist file into a deduplicated list of candidate strings."""
    words: List[str] = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            w = raw.rstrip("\r\n")
            if w.startswith("\ufeff"):
                w = w[1:]
            if not w or len(w) > MAX_LINE:
                continue
            if w in seen:
                continue
            seen.add(w)
            words.append(w)
    return words


def count_lines(path: str) -> int:
    """Fast line count (no dedupe) for pre-run sizing in the GUI."""
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return n


def ensure_builtin(defaults: Optional[dict] = None) -> None:
    """Create builtin wordlists if missing (first run / dev convenience).

    *defaults* maps filename -> content. Only synthetic educational entries
    are ever written — never real breach data (see memory.md §2).
    """
    d = os.path.join(_resource_root(), "wordlists")
    os.makedirs(d, exist_ok=True)
    for fn, content in (defaults or {}).items():
        p = os.path.join(d, fn)
        if not os.path.isfile(p):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
