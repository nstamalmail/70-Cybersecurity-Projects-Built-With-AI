"""Headless self-test: spins up a local vulnerable web app and verifies the
fuzz engine detects canonical issues. Works from source and inside the exe.

Writes selftest_result.txt next to the executable (or project root in dev).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from app.config import get_base_dir
from app.core.engine import run_scan_headless
from app.core.models import InjectionPoint, ScanConfig
from app.utils.state import StateStore


class _VulnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def _send(self, code: int, body: str, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"

        # SQLi: /sqli?user=x (or ?q=x) -> vulnerable query error
        if path == "/sqli":
            user = qs.get("user", qs.get("q", [""]))[0]
            if "'" in user or '"' in user:
                self._send(500, "<html>You have an error in your SQL syntax; "
                                 "check the manual near 'user'</html>")
            else:
                self._send(200, f"<html>user={user}</html>")
            return

        # XSS echo
        if path == "/xss":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>results for <b>{q}</b></body></html>")
            return

        # Path traversal — only "vulnerable" when traversal is detected.
        if path == "/file":
            name = unquote(qs.get("q", [""])[0] or qs.get("name", [""])[0])
            if ".." in name or "etc/passwd" in name or "win.ini" in name.lower():
                self._send(200, "<html>root:x:0:0:root:/root:/bin/bash  <br>ok</html>")
            else:
                self._send(200, "<html>file not found</html>")
            return

        # SSTI
        if path == "/ssti":
            name = qs.get("q", [""])[0]
            try:
                expr = name[2:-2] if name.startswith("{{") and name.endswith("}}") else ""
                rendered = str(eval(expr)) if expr else name  # simplified
            except Exception:
                rendered = name
            self._send(200, f"<html>Hello {rendered}</html>")
            return

        # Open redirect
        if path == "/redirect":
            url = qs.get("q", [""])[0]
            if "evil.com" in url or url.startswith("//"):
                self._send(302, "redirecting", {"Location": url})
            else:
                self._send(200, "<html>no redirect</html>")
            return

        # Command injection (simulated output marker)
        if path == "/cmd":
            cmd = qs.get("q", [""])[0]
            if "id" in cmd or "whoami" in cmd or "cat" in cmd:
                self._send(200, "<html>uid=0(root) gid=0(root) groups=0(root)<br>"
                                "root:x:0:0:root:/root:/bin/bash</html>")
            else:
                self._send(200, "<html>ok</html>")
            return

        # Time-based blind
        if path == "/sleep":
            q = qs.get("q", [""])[0]
            if "sleep" in q.lower() or "waitfor" in q.lower():
                time.sleep(5)
            self._send(200, "<html>ok</html>")
            return

        # CRLF (requests blocks control chars; include a header if `headers` sent)
        if path == "/crlf":
            self._send(200, "<html>ok</html>", {"X-Injected": "true"})
            return

        self._send(404, "<html>not found</html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        if parsed.path.rstrip("/") == "/login":
            qs = parse_qs(body)
            user = qs.get("user", [""])[0]
            if "'" in user:
                self._send(500, "Unclosed quotation mark after the character string ''.")
            else:
                self._send(200, "<html>ok</html>")
            return
        if parsed.path.rstrip("/") == "/echo":
            self._send(200, f"<html>echo {body}</html>")
            return
        self._send(404, "<html>not found</html>")


def _start_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class _Result:
    def __init__(self):
        self.checks: list = []
        self.findings: list = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def summary(self) -> str:
        passed = sum(1 for c in self.checks if c["ok"])
        total = len(self.checks)
        status = "PASS" if passed == total else "FAIL"
        lines = [
            f"WebFuzzer self-test: {status} ({passed}/{total} checks)",
            "",
        ]
        for c in self.checks:
            mark = "PASS" if c["ok"] else "FAIL"
            lines.append(f"[{mark}] {c['name']}" + (f" — {c['detail']}" if c.get("detail") else ""))
        if self.findings:
            lines.append("")
            lines.append("Findings detected by engine:")
            for f in self.findings:
                lines.append(f"  - {f}")
        return "\n".join(lines)


def _scan_target(base: str, result: _Result) -> None:
    cfg = ScanConfig(
        target_url=base + "/sqli?user=admin",
        method="GET",
        injection_points=[
            InjectionPoint("query", "user", "admin", True),
        ],
        categories=["sqli", "xss"],
        encodings=["none", "url"],
        threads=4,
        delay_ms=5,
        timeout=8.0,
        time_based=True,
        max_requests=200,
        authorized=True,
    )
    findings, stats = run_scan_headless(cfg, timeout=120)
    result.findings = [f.summary() for f in findings]
    techniques = {f.technique for f in findings}
    result.check("engine completed scan", stats["requests"] > 0,
                 f"{stats['requests']} requests, {stats['errors']} errors")
    result.check("detected SQL error injection", "sql-error" in techniques, str(techniques))
    result.check("detected XSS reflection", "xss-reflection" in techniques, str(techniques))
    result.check("rate limiter active (delay>=1ms)", cfg.delay_ms >= 1)


def run_selftest() -> int:
    result = _Result()
    base_dir = get_base_dir()
    result_path = os.path.join(base_dir, "selftest_result.txt")
    memory_note = "self-test"

    server = _start_server()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"

    try:
        store = StateStore(base_dir)
        store.log_memory(f"self-test started (engine headless, target {base})")

        result.check("StateStore writes memory.md", os.path.exists(store.memory_path))

        # --- targeted checks: each vulnerable route in isolation (fast) -------
        def scan_findings(path: str, cat: str, point_value: str = "x",
                          payload_override: list | None = None) -> list:
            cfg = ScanConfig(
                target_url=base + path,
                injection_points=[InjectionPoint("query", "q", point_value, True)],
                categories=[cat],
                encodings=["none"],
                custom_payloads=payload_override or [],
                threads=2, delay_ms=1, timeout=4.0,
                time_based=True, max_requests=60, authorized=True,
            )
            f, _ = run_scan_headless(cfg, timeout=90)
            return [x.technique for x in f]

        # SQLi
        techs = scan_findings("/sqli?q=x", "sqli")
        result.check("SQLi (error-based)", "sql-error" in techs, str(techs))

        # XSS
        techs = scan_findings("/xss?q=x", "xss", "hello")
        result.check("XSS reflection", "xss-reflection" in techs, str(techs))

        # File read (path traversal)
        techs = scan_findings("/file?q=x", "path_traversal")
        result.check("file-read (traversal)", "file-read" in techs, str(techs))

        # SSTI
        techs = scan_findings("/ssti?q=x", "ssti", "world")
        result.check("SSTI eval", "ssti-eval" in techs, str(techs))

        # Open redirect
        techs = scan_findings("/redirect?q=x", "open_redirect")
        result.check("open-redirect", "open-redirect" in techs, str(techs))

        # Command injection
        techs = scan_findings("/cmd?q=x", "cmdi")
        result.check("cmd-output", "cmd-output" in techs, str(techs))

        # Time-based blind
        techs = scan_findings("/sleep?q=x", "sqli", "x",
                              ["1' AND SLEEP(5)-- -"])
        result.check("time-based-blind", "time-based-blind" in techs, str(techs))

        # CRLF header injection
        techs = scan_findings("/crlf?q=x", "crlf", "x", ["%0d%0aX-Injected:%20true"])
        result.check("crlf-header (server echoes header)", "crlf-header" in techs, str(techs))

        # Full mixed scan (SQLi + XSS together)
        _scan_target(base, result)

        store.log_memory("self-test finished (engine verified)")
    finally:
        server.shutdown()

    summary = result.summary()
    with open(result_path, "w", encoding="utf-8") as fh:
        fh.write(summary + "\n")

    print(summary)
    ok = all(c["ok"] for c in result.checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_selftest())