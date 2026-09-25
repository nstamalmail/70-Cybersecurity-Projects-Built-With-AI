"""Headless self-test for SIDT: spins up a local vulnerable web app and
verifies the engine detects SQL injection signals. Works from source and
inside the exe. Writes selftest_result.txt next to the executable.
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

    def _send(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"

        # Error-based SQLi: quote triggers a MySQL-style error
        if path == "/search":
            user = qs.get("user", [""])[0]
            if "'" in user or '"' in user or "\\" in user:
                self._send(500, "<html><b>Warning</b>: You have an error in your "
                                "SQL syntax; check the manual that corresponds to "
                                "your MySQL server version near ''</html>")
            else:
                self._send(200, f"<html>results for {user}</html>")
            return

        # Boolean-based blind: 1=1 (quoted or bare) renders items page,
        # 1=2 renders the empty result page
        if path == "/item":
            q = unquote(qs.get("id", [""])[0])
            q_norm = q.replace("'", "").replace('"', "").lower()
            if "1=2" in q_norm:
                self._send(200, "<html><body>no items found</body></html>")
            elif "1=1" in q_norm or q.strip() in ("1", "2", "3"):
                self._send(200, "<html><body><ul><li>item A</li><li>item B</li>"
                                "</ul></body></html>")
            else:
                self._send(200, f"<html><body>item {q}</body></html>")
            return

        # Time-based: SLEEP delays the response
        if path == "/sleep":
            q = qs.get("q", [""])[0]
            if "sleep(" in q.lower() or "waitfor" in q.lower():
                time.sleep(6)
            self._send(200, "<html>ok</html>")
            return

        # Union-based: echo the marker columns back
        if path == "/list":
            q = qs.get("cat", [""])[0]
            marker = "sidt7f3a"
            if marker in q:
                self._send(200, f"<html><table><tr><td>{marker}</td></tr></table></html>")
            else:
                self._send(200, "<html><table><tr><td>books</td></tr></table></html>")
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
        lines = [f"SIDT self-test: {status} ({passed}/{total} checks)", ""]
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
    """Run ScanEngine headlessly and drain the event queue."""
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
        # --- error-based -----------------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/search?user=admin",
            parameters=[Parameter("query", "user", "admin")],
            techniques=["error", "boolean"], safe_mode=True,
            delay_ms=1, timeout=6.0, authorized=True)
        engine, findings = _run_scan(cfg)
        techs = {f.technique for f in findings}
        result.check("error-based SQLi detected", "error" in techs, str(techs))
        result.check("engine sent requests", engine.stats["requests"] > 0,
                     f"{engine.stats['requests']} requests")
        result.check("DBMS fingerprint (mysql)", any(
            f.dbms_hint == "mysql" for f in findings), str(
            [f.dbms_hint for f in findings]))
        result.check("remediation attached", all(
            "parameterized" in (f.remediation or "").lower() for f in findings))
        store.log_memory(f"self-test error-based scan: {len(findings)} findings")

        # --- boolean-based ----------------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/item?id=5",
            parameters=[Parameter("query", "id", "5")],
            techniques=["boolean"], safe_mode=True,
            delay_ms=1, timeout=6.0, authorized=True)
        engine, findings = _run_scan(cfg)
        techs = {f.technique for f in findings}
        result.check("boolean-based SQLi detected", "boolean" in techs, str(techs))

        # --- safe mode blocks time/union -------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/sleep?q=1",
            parameters=[Parameter("query", "q", "1")],
            techniques=["time", "union"], safe_mode=True,
            delay_ms=1, timeout=6.0, authorized=True)
        engine, findings = _run_scan(cfg)
        result.check("safe mode blocks time/union payloads", len(findings) == 0,
                     f"{len(findings)} findings")
        result.check("safe mode sent only baseline requests",
                     engine.stats["requests"] <= 2,
                     f"{engine.stats['requests']} requests")

        # --- time-based (opt-in) ----------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/sleep?q=1",
            parameters=[Parameter("query", "q", "1")],
            techniques=["time"], safe_mode=False, time_threshold_s=4.0,
            delay_ms=1, timeout=20.0, authorized=True)
        engine, findings = _run_scan(cfg)
        techs = {f.technique for f in findings}
        result.check("time-based SQLi detected (opt-in)", "time" in techs, str(techs))

        # --- union-based (opt-in) ----------------------------------------------
        cfg = ScanConfig(
            target_url=f"{base}/list?cat=books",
            parameters=[Parameter("query", "cat", "books")],
            techniques=["union"], safe_mode=False,
            delay_ms=1, timeout=6.0, authorized=True)
        engine, findings = _run_scan(cfg)
        techs = {f.technique for f in findings}
        result.check("union-based SQLi detected (opt-in)", "union" in techs, str(techs))

        # --- report generation --------------------------------------------------
        from app.core.report import export_all
        scan_meta = {"id": 1, "target": base, "parameters_tested": 4,
                     "total_requests": 30, "findings_count": 2, "errors": 0,
                     "safe_mode": True, "waf": ""}
        fdicts = [f.to_dict() for f in findings] or [{
            "severity": "high", "parameter_location": "query",
            "parameter_name": "cat", "technique": "union",
            "confidence": "high", "dbms_hint": "mysql", "signal": "marker",
            "payload": "x", "url": base, "method": "GET",
            "baseline_request": "GET /", "injected_request": "GET /?cat=x",
            "baseline_response_snippet": "a", "injected_response_snippet": "b",
            "response_delta": {}, "remediation": "parameterize",
            "references": []}]
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
