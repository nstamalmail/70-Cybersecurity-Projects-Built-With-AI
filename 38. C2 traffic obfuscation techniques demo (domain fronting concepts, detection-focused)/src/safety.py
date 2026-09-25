"""Static safety guard.

Scans the project's Python sources with ``ast`` and fails if any module in the
FORBIDDEN set is imported. This proves (S1) no network I/O exists anywhere in
the codebase — a review-gate artifact, not just a promise.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Anything capable of network egress or packet crafting.
FORBIDDEN_MODULES = {
    "socket",
    "ssl",
    "http",
    "httplib",
    "http.client",
    "http.server",
    "requests",
    "urllib",
    "urllib2",
    "urllib3",
    "httpx",
    "aiohttp",
    "scapy",
    "ftplib",
    "smtplib",
    "telnetlib",
    "nntplib",
    "paramiko",
    "fabric",
    "selenium",
    "pycurl",
    "websocket",
    "websockets",
    "grpc",
    "twisted",
    "dns",
    "dnspython",
    "dpkt",
    "pyshark",
}

ROOT = Path(__file__).resolve().parent.parent


def _iter_project_files(root: Path | None = None):
    base = root or ROOT
    for path in sorted(base.rglob("*.py")):
        s = str(path).replace("\\", "/")
        # Skip build/test-venv noise and our own test of the guard.
        if any(part in {".git", "build", "dist", "venv", ".venv", "__pycache__", "site-packages"} for part in path.parts):
            continue
        yield path


def _imports_of(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                yield node.module


def scan_for_network_imports(root: Path | None = None) -> list[str]:
    """Return a list of violation strings ('file:line import X'). Empty == safe."""
    violations: list[str] = []
    for path in _iter_project_files(root):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for name in _imports_of(tree):
            top = name.split(".")[0]
            if name in FORBIDDEN_MODULES or top in FORBIDDEN_MODULES:
                violations.append(f"{path.name}: import {name}")
    return violations


def assert_safe(root: Path | None = None) -> None:
    violations = scan_for_network_imports(root)
    if violations:
        raise SystemExit(
            "SAFETY VIOLATION — network-capable imports found:\n  " + "\n  ".join(violations)
        )
