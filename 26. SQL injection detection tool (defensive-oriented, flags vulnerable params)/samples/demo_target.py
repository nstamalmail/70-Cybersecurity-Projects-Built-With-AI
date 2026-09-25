"""Deliberately vulnerable demo web app for SIDT (localhost only).

Run:  python samples/demo_target.py
Then scan: http://127.0.0.1:8765/search?user=admin
"""

from __future__ import annotations

import time
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
            self._send(200, """<html><head><title>SIDT demo target</title></head>
<body><h1>SIDT demo target</h1>
<ul>
<li><a href="/search?user=admin">/search?user=admin</a> — error-based SQLi</li>
<li><a href="/item?id=5">/item?id=5</a> — boolean-based blind SQLi</li>
<li><a href="/list?cat=books">/list?cat=books</a> — union-based SQLi</li>
<li><a href="/sleep?q=1">/sleep?q=1</a> — time-based blind SQLi</li>
</ul></body></html>""")
            return

        if path == "/search":
            user = qs.get("user", [""])[0]
            if "'" in user or '"' in user or "\\" in user:
                self._send(500, "<html><b>Warning</b>: You have an error in your "
                                "SQL syntax; check the manual that corresponds to "
                                "your MySQL server version near ''</html>")
            else:
                self._send(200, f"<html>results for {user}</html>")
            return

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

        if path == "/list":
            q = qs.get("cat", [""])[0]
            marker = "sidt7f3a"
            if marker in q:
                self._send(200, f"<html><table><tr><td>{marker}</td></tr></table></html>")
            else:
                self._send(200, "<html><table><tr><td>books</td></tr></table></html>")
            return

        if path == "/sleep":
            q = qs.get("q", [""])[0]
            if "sleep(" in q.lower() or "waitfor" in q.lower():
                time.sleep(6)
            self._send(200, "<html>ok</html>")
            return

        self._send(404, "<html>not found</html>")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"SIDT demo target listening on http://127.0.0.1:{PORT} (Ctrl+C to stop)")
    print("Scannable endpoints:")
    print("  /search?user=admin   error-based")
    print("  /item?id=5           boolean-based blind")
    print("  /list?cat=books      union-based")
    print("  /sleep?q=1           time-based blind")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
