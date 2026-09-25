"""Headless self-test for XPT: spins up a local vulnerable web app and verifies
the engine detects reflected XSS with context/encoding classification.
Writes selftest_result.txt next to the executable.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from app.config import get_base_dir
from app.core.engine import ScanEngine
from app.core.models import Parameter, ScanConfig
from app.utils.state import StateStore


class _VulnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
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

        # Raw reflection in HTML body (vulnerable)
        if path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>results for <b>{q}</b></body></html>")
            return

        # Reflection inside an attribute (vulnerable break-out)
        if path == "/profile":
            name = unquote(qs.get("name", [""])[0])
            self._send(200, f"<html><body><input value=\"{name}\"></body></html>")
            return

        # Encoded reflection (safe-ish: html-escaped by server)
        if path == "/safe":
            q = qs.get("q", [""])[0]
            esc = (q.replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))
            self._send(200, f"<html><body>results for {esc}</body></html>")
            return

        # Reflection inside a JS string (vulnerable)
        if path == "/script":
            q = unquote(qs.get("q", [""])[0])
            self._send(200, f"<html><head><script>var name = '{q}';</script>"
                            "</head><body>ok</body></html>")
            return

        # DOM-sink style page (static analysis target)
        if path == "/dom":
            self._send(200, "<html><head><script>"
                            "document.getElementById('out').innerHTML = location.hash;"
                            "</script></head><body><div id='out'></div></body></html>")
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
        lines = [f"XPT self-test: {status} ({passed}/{total} checks)", ""]
        for c in self.checks:
            mark = "PASS" if c["ok"] else "FAIL"
            lines.append(f"[{mark}] {c['name']}" +
                         (f" — {c['detail']}" if c.get("detail") else ""))
        if self.findings:
            lines.append("")
            lines.append("Findings detected by engine:")
            for f in self.findings:
                lines.append(f"  - {f}")
        return "\n".join(lines)


def _run_scan(cfg: ScanConfig, events_timeout: float = 90.0):
    import queue as _q
    events = _q.Queue()
    engine = ScanEngine(cfg, events)
    engine.start()
    findings = []
    deadline = time.time() + events_timeout
    finished = False
    while time.time() < deadline and not finished:
        try:
            ev = events.get(timeout=0.2)
        except Exception:
            continue
        if ev["type"] == "finding":
            findings.append(ev["finding"])
        elif ev["type"] == "scan_finished":
            finished = True
    return engine, findings


def run_selftest() -> int:
    result = _Result()
    base_dir = get_base_dir()
    result_path = os.path.join(base_dir, "selftest_result.txt")

    server = _start_server()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"

    store = StateStore(base_dir)
    store.log_memory(f"self-test started (engine headless, target {base})")
    result.check("StateStore writes memory.md", os.path.exists(store.memory_path))

    try:
        # --- raw reflection in HTML body -------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/search?q=hello",
            parameters=[Parameter("query", "q", "hello")],
            contexts=["html_body"], delay_ms=1, timeout=6.0,
            max_requests=200, authorized=True)
        engine, findings = _run_scan(cfg)
        result.check("reflected XSS detected (html_body)", len(findings) > 0,
                     f"{len(findings)} findings")
        result.check("context classified as html_body", any(
            f.context == "html_body" for f in findings),
            str({f.context for f in findings}))
        result.check("engine sent requests", engine.stats["requests"] > 0,
                     f"{engine.stats['requests']} requests")

        # --- attribute break-out ----------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/profile?name=guest",
            parameters=[Parameter("query", "name", "guest")],
            contexts=["html_attribute"], delay_ms=1, timeout=6.0,
            max_requests=200, authorized=True)
        _, findings = _run_scan(cfg)
        result.check("attribute break-out detected", any(
            f.context == "html_attribute" for f in findings),
            str({f.context for f in findings}))

        # --- js string break-out ----------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/script?q=world",
            parameters=[Parameter("query", "q", "world")],
            contexts=["js_string"], delay_ms=1, timeout=6.0,
            max_requests=200, authorized=True)
        _, findings = _run_scan(cfg)
        result.check("js_string break-out detected", any(
            f.context == "js_string" for f in findings),
            str({f.context for f in findings}))

        # --- encoded reflection is NOT a high finding ---------------------------
        cfg = ScanConfig(
            target_url=f"{base}/safe?q=hello",
            parameters=[Parameter("query", "q", "hello")],
            contexts=["html_body", "html_attribute"], delay_ms=1, timeout=6.0,
            max_requests=200, authorized=True)
        _, findings = _run_scan(cfg)
        result.check("html-encoded reflection not flagged high",
                     all(f.severity != "high" for f in findings),
                     str([f.severity for f in findings]))

        # --- DOM sink static analysis -------------------------------------------
        from app.core.payloads import DOM_SINKS
        js = ("document.getElementById('out').innerHTML = location.hash;")
        result.check("DOM sink pattern matched",
                     any(s in js for s in DOM_SINKS))

        # --- report generation ----------------------------------------------------
        from app.core.report import export_all
        scan_meta = {"id": 1, "target": base, "parameters_tested": 4,
                     "payloads_used": 12, "total_requests": 40,
                     "findings_count": 3, "errors": 0, "csp_present": False}
        fdicts = [f.to_dict() for f in findings] or [{
            "severity": "high", "xss_type": "reflected", "context": "html_body",
            "parameter_location": "query", "parameter_name": "q",
            "payload": "<script>alert(1)</script>", "url": base,
            "method": "GET", "signal": "raw reflection",
            "reflection_snippet": "x", "request": "GET /",
            "response_snippet": "y", "encoding_applied": "none",
            "browser_confirmed": False, "confirmation_method": "reflection",
            "remediation": "encode", "references": []}]
        outdir = os.path.join(base_dir, "reports")
        paths = export_all(scan_meta, fdicts, outdir)
        result.check("HTML report exported", os.path.exists(paths["html"]))
        result.check("CSV report exported", os.path.exists(paths["csv"]))
        result.check("JSON report exported", os.path.exists(paths["json"]))
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
