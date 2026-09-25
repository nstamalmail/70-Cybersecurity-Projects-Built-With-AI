"""Deliberately vulnerable demo web app for XPT (localhost only).

Run:  python samples/demo_target.py
Then scan: http://127.0.0.1:8765/search?q=hello
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

PORT = 8765


class DemoHandler(BaseHTTPRequestHandler):
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

        if path == "/":
            self._send(200, """<html><head><title>XPT demo target</title></head>
<body><h1>XPT demo target</h1>
<ul>
<li><a href="/search?q=hello">/search?q=hello</a> — reflected XSS in HTML body</li>
<li><a href="/profile?name=guest">/profile?name=guest</a> — XSS via attribute break-out</li>
<li><a href="/script?q=world">/script?q=world</a> — XSS via JS string break-out</li>
<li><a href="/safe?q=hello">/safe?q=hello</a> — properly encoded (should not alert)</li>
<li><a href="/comment">/comment</a> — POST comment box (stored-style demo)</li>
</ul></body></html>""")
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>results for <b>{q}</b></body></html>")
            return

        if path == "/profile":
            name = unquote(qs.get("name", [""])[0])
            self._send(200, f"<html><body><input value=\"{name}\"></body></html>")
            return

        if path == "/script":
            q = unquote(qs.get("q", [""])[0])
            self._send(200, f"<html><head><script>var name = '{q}';</script>"
                            "</head><body>ok</body></html>")
            return

        if path == "/safe":
            q = qs.get("q", [""])[0]
            esc = (q.replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))
            self._send(200, f"<html><body>results for {esc}</body></html>")
            return

        if path == "/comment":
            self._send(200, "<html><body><h1>Comment box (POST)</h1>"
                            "<form method='post' action='/comment'>"
                            "<textarea name='comment'></textarea>"
                            "<input type='submit'></form></body></html>")
            return

        self._send(404, "<html>not found</html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        if parsed.path.rstrip("/") == "/comment":
            qs = parse_qs(body)
            comment = qs.get("comment", [""])[0]
            # stored-style echo (vulnerable on purpose)
            self._send(200, f"<html><body>comment saved: {comment}</body></html>")
            return
        self._send(404, "<html>not found</html>")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"XPT demo target listening on http://127.0.0.1:{PORT} (Ctrl+C to stop)")
    print("Scannable endpoints:")
    print("  /search?q=hello      reflected XSS in HTML body")
    print("  /profile?name=guest  attribute break-out")
    print("  /script?q=world      JS string break-out")
    print("  /safe?q=hello        encoded (safe) reflection")
    print("  /comment             POST stored-style demo")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
