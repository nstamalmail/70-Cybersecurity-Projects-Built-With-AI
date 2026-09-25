"""Smoke test: construct the MMPS GUI offscreen and simulate a result row."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "mmps"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("MMPS_DATA", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_out")))

from PySide6.QtWidgets import QApplication

app = QApplication(sys.argv)

import theme
import main as m
from engine import PortResult, ScanResult

app.setStyleSheet(theme.STYLESHEET)

win = m.MainWindow()
assert win.table.columnCount() == 5, "table columns"
win._apply_result(PortResult(443, "OPEN", "https", "nginx 1.24"))
assert win.table.rowCount() == 1, "table row added"
assert win.console is not None

# Simulate a completed scan -> export enabled
res = ScanResult(scan_id="smoke", target="localhost", resolved_ip="127.0.0.1",
                 scan_mode="tcp_connect", timestamp=__import__("datetime").datetime.now())
res.ports = [PortResult(22, "OPEN", "ssh", "OpenSSH 9.2")]
res.total_scanned = 100
res.open_count = 1
win._apply_done(res, None)
assert win.export_btn.isEnabled(), "export enabled after done"

# Export all formats programmatically
import reporting
res.ports = [PortResult(22, "OPEN", "ssh", "OpenSSH 9.2"),
             PortResult(80, "OPEN", "http", "nginx 1.24"),
             PortResult(445, "OPEN", "microsoft-ds", None),
             PortResult(443, "OPEN", "https", "Apache 2.4"),
             PortResult(3389, "OPEN", "ms-wbt", None)]
res.open_count = len(res.ports)
for p in res.ports:
    p.risk()
for fmt in ("txt", "json", "csv", "html", "pdf"):
    out = reporting.export(res, fmt, os.path.join(os.environ["MMPS_DATA"], f"smoke.{fmt}"))
    assert os.path.getsize(out) > 150, f"{fmt} too small ({os.path.getsize(out)} bytes)"
    print(f"  report {fmt}: {os.path.getsize(out)} bytes")

print("MMPS GUI SMOKE TEST PASSED")
