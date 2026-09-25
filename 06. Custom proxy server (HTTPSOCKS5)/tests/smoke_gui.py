"""Smoke test: CPS proxy engine end-to-end + GUI + reports."""
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src", "cps"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("CPS_DATA", os.path.abspath(os.path.join(HERE, "..", "test_out")))

import time
import urllib.request

import reporting
from engine import FilterEngine, ProxyConfig, ProxyServer, session_from_traffic

os.makedirs(os.environ["CPS_DATA"], exist_ok=True)

# 1) Filter engine unit checks
flt = FilterEngine(["ads.example.com", "*.tracker.net", "203.0.113.0/24", "re:blocked-.*\\.net"])
assert flt.check("ads.example.com") == "exact match"
assert flt.check("x.tracker.net") == "wildcard *.tracker.net"
assert flt.check("203.0.113.9").startswith("CIDR")
assert flt.check("blocked-foo.net").startswith("regex")
assert flt.check("example.org") is None
print("  filter engine OK")

# 2) Live proxy flow: start server, make an HTTP CONNECT request via urllib proxy
records = []
cfg = ProxyConfig(listen_host="127.0.0.1", listen_port=8899, protocol_mode="auto",
                  blocklist_enabled=True, blocklist_rules=["*.blocked.example"])
srv = ProxyServer(cfg, on_event=records.append)
srv.start()
assert srv.running, "server did not start"
time.sleep(0.3)

# local HTTP server as target
from http.server import BaseHTTPRequestHandler, HTTPServer


class TinyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"hello through proxy"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


tiny = HTTPServer(("127.0.0.1", 8901), TinyHandler)
import threading
threading.Thread(target=tiny.serve_forever, daemon=True).start()

# HTTP proxy request (urllib uses GET absolute-URI... not CONNECT; use raw CONNECT)
import socket


def http_connect_test():
    s = socket.socket()
    s.settimeout(3)
    s.connect(("127.0.0.1", 8899))
    s.sendall(b"CONNECT 127.0.0.1:8901 HTTP/1.1\r\nHost: 127.0.0.1:8901\r\n\r\n")
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(1024)
    assert b"200" in resp, resp
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    data = b""
    try:
        while b"hello through proxy" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    assert b"hello through proxy" in data, data
    s.close()


http_connect_test()
print("  HTTP CONNECT tunnel OK")


def socks5_test():
    s = socket.socket()
    s.settimeout(3)
    s.connect(("127.0.0.1", 8899))
    s.sendall(b"\x05\x01\x00")            # version, 1 method, no-auth
    assert s.recv(2) == b"\x05\x00"
    req = b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + (8901).to_bytes(2, "big")
    s.sendall(req)
    resp = s.recv(1024)
    assert resp[1] == 0, resp
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    data = b""
    try:
        while b"hello through proxy" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    assert b"hello through proxy" in data, data
    s.close()


socks5_test()
print("  SOCKS5 tunnel OK (auto-detect on same port)")

# blocked destination
def blocked_test():
    s = socket.socket()
    s.settimeout(5)
    s.connect(("127.0.0.1", 8899))
    s.sendall(b"CONNECT evil.blocked.example:443 HTTP/1.1\r\n\r\n")
    resp = s.recv(1024)
    assert b"403" in resp, resp
    s.close()


blocked_test()
print("  blocklist enforcement OK")

time.sleep(0.5)
srv.stop()
tiny.shutdown()
status_counts = {}
for r in records:
    status_counts[r.get("status")] = status_counts.get(r.get("status"), 0) + 1
print("  records:", status_counts)
assert status_counts.get("ALLOWED", 0) >= 2 and status_counts.get("BLOCKED", 0) >= 1

# 3) Session aggregation + reports
session = session_from_traffic("cps-smoke", cfg.to_dict(), records)
assert session.total_connections == len(records)
for fmt in ("txt", "json", "csv", "html", "pdf"):
    out = reporting.export(session, fmt, os.path.join(os.environ["CPS_DATA"], f"cps.{fmt}"))
    size = os.path.getsize(out)
    assert size > 200, (fmt, size)
    print(f"  report {fmt}: {size} bytes")

# 4) Import path (JSONL sample)
def load_jsonl(path):
    recs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                recs.append(json.loads(line))
    return recs


sample = load_jsonl(os.path.join(HERE, "..", "sample_data", "traffic_corp_morning.jsonl"))
assert len(sample) == 18, len(sample)
sess2 = session_from_traffic("cps-sample", cfg.to_dict(), sample)
assert sess2.total_connections == 18
assert sess2.blocked_count == 4, sess2.blocked_count
assert sess2.unique_destinations >= 12
print(f"  sample import OK: {sess2.total_connections} conns, "
      f"{sess2.blocked_count} blocked, {sess2.unique_destinations} unique dests")

# 5) GUI construct
from PySide6.QtWidgets import QApplication
app = QApplication(sys.argv)
import theme
import main as m
app.setStyleSheet(theme.STYLESHEET)
win = m.MainWindow()
assert win.traffic_tbl.columnCount() == 8
print("  GUI OK")

print("CPS SMOKE TEST PASSED")
