#!/usr/bin/env python3
"""WebFuzzer demo target — a deliberately vulnerable local web app.

Run it, then point WebFuzzer at the URLs below (all served on one host/port).
This is sample input data for manual testing; every route is intentionally
insecure so the fuzzer can detect real, reproducible findings.

Usage:
    python samples/demo_target.py            # serves on 127.0.0.1:8765

Routes (sample input for the Target tab):
    http://127.0.0.1:8765/sqli?user=admin        -> error-based SQLi
    http://127.0.0.1:8765/xss?q=hello            -> reflected XSS
    http://127.0.0.1:8765/file?name=readme.txt   -> path traversal / file read
    http://127.0.0.1:8765/ssti?name=world        -> template injection
    http://127.0.0.1:8765/redirect?url=/home     -> open redirect
    http://127.0.0.1:8765/cmd?host=localhost     -> command injection
    http://127.0.0.1:8765/sleep?q=1              -> time-based blind SQLi
    http://127.0.0.1:8765/crlf?lang=en           -> CRLF header injection
    POST http://127.0.0.1:8765/login  (form: user=&pass=) -> SQLi in POST body

Authorized-testing demo only — do not expose this server beyond localhost.
"""

import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


class DemoVulnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter console
        print("[demo-target] %s" % (fmt % args))

    # ---------------------------------------------------------------- helpers
    def _send(self, code: int, body: str, extra_headers=None, delay: float = 0.0):
        if delay:
            time.sleep(delay)
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _table(user: str) -> str:
        # Simulated DB errors when quotes break out of the query.
        if "'" in user or '"' in user:
            return ("<html><body>You have an error in your SQL syntax; check the "
                    "manual that corresponds to your MySQL server version for the "
                    "right syntax to use near '" + user + "'</body></html>")
        return f"<html><body>Welcome, {user}! (user row fetched)</body></html>"

    # ------------------------------------------------------------------- GET
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"
        first = lambda k, d="": qs.get(k, [d])[0]  # noqa: E731

        if path == "/":  # landing page listing the routes
            self._send(200, "<html><body><h1>WebFuzzer demo target</h1>"
                            "<p>Deliberately vulnerable. Authorized testing only.</p>"
                            "<ul><li>/sqli?user=</li><li>/xss?q=</li><li>/file?name=</li>"
                            "<li>/ssti?name=</li><li>/redirect?url=</li><li>/cmd?host=</li>"
                            "<li>/sleep?q=</li><li>/crlf?lang=</li></ul></body></html>")
            return

        if path == "/sqli":
            self._send(200 if not ("'" in first("user") or '"' in first("user"))
                       else 500, self._table(first("user")))
            return

        if path == "/xss":
            self._send(200, f"<html><body>results for <b>{first('q')}</b></body></html>")
            return

        if path == "/file":
            name = unquote(first("name"))
            if ".." in name or "etc/passwd" in name or "win.ini" in name.lower():
                self._send(200, "<html><body>root:x:0:0:root:/root:/bin/bash<br>"
                                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</body></html>")
            else:
                self._send(200, f"<html><body>No such file: {name}</body></html>")
            return

        if path == "/ssti":
            name = first("name")
            if "{{" in name and "}}" in name:
                # Tiny "template engine": evaluates integer arithmetic inside {{ }}.
                expr = name.replace("{{", "").replace("}}", "").strip()
                try:
                    val = eval(expr, {"__builtins__": {}}, {}) if expr.replace("*", "").isdigit() else name
                except Exception:
                    val = name
            else:
                val = name
            self._send(200, f"<html><body>Hello {val}</body></html>")
            return

        if path == "/redirect":
            url = first("url")
            if url.startswith("//") or "evil.com" in url or url.startswith("http"):
                self._send(302, "redirecting", {"Location": url})
            else:
                self._send(200, "<html><body>no redirect</body></html>")
            return

        if path == "/cmd":
            host = first("host")
            if any(t in host for t in (";", "|", "`", "$(")):
                self._send(200, "<html><body><pre>uid=0(root) gid=0(root) "
                                "groups=0(root)</pre></body></html>")
            else:
                self._send(200, f"<html><body>pinging {host}…</body></html>")
            return

        if path == "/sleep":
            q = first("q").lower()
            delay = 0.0
            if "sleep(" in q or "waitfor" in q:
                delay = 5.0
            self._send(200, "<html><body>ok</body></html>", delay=delay)
            return

        if path == "/crlf":
            lang = first("lang")
            if "%0d%0a" in lang.lower() or "\r\n" in lang:
                # Simulate a back-end that would split headers.
                self._send(200, "<html><body>language set</body></html>",
                           {"X-Injected": "true"})
            else:
                self._send(200, f"<html><body>language set to {lang}</body></html>")
            return

        self._send(404, "<html><body>not found</body></html>")

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        path = parsed.path.rstrip("/") or "/"

        if path == "/login":
            form = parse_qs(body)
            user = form.get("user", [""])[0]
            if "'" in user or '"' in user:
                self._send(500, "Unclosed quotation mark after the character string ''.")
            else:
                self._send(200, "<html><body>login ok</body></html>")
            return

        if path == "/echo":
            self._send(200, f"<html><body>echo {body}</body></html>")
            return

        self._send(404, "<html><body>not found</body></html>")


def main() -> int:
    ap = argparse.ArgumentParser(description="WebFuzzer demo (vulnerable) target")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), DemoVulnHandler)
    print(f"[demo-target] Serving on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    print("[demo-target] Sample URLs are listed in samples/README.md")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[demo-target] bye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
