"""Smoke test: DRCP GUI construction, sample import, report exports."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src", "drcp"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("DRCP_DATA", os.path.abspath(
    os.path.join(HERE, "..", "test_out")))

from PySide6.QtWidgets import QApplication

app = QApplication(sys.argv)

import theme
import main as m
import reporting
from engine import LabController, session_from_dict

app.setStyleSheet(theme.STYLESHEET)

win = m.MainWindow()
assert win.cache_tbl.columnCount() == 5
assert win.tl_tbl.columnCount() == 4

# Import the sample session through the same code path as the menu action
raw = json.load(open(os.path.join(HERE, "..", "sample_data", "poisoning_success_session.json"),
                     encoding="utf-8"))
win.session = session_from_dict(raw)
assert win.session.poisoning_successful is True
assert win.session.attempts == 3

# Export every format
os.makedirs(os.environ["DRCP_DATA"], exist_ok=True)
for fmt in ("txt", "json", "csv", "html", "pdf"):
    out = reporting.export(win.session, fmt, os.path.join(os.environ["DRCP_DATA"], f"drcp.{fmt}"))
    size = os.path.getsize(out)
    assert size > 200, (fmt, size)
    print(f"  report {fmt}: {size} bytes")

# Engine sanity: lab starts and answers a query
lab = LabController()
ok, msg = lab.start_lab(resolver_port=5460, upstream_port=5450)
assert ok, msg
ans, status = lab.trigger_query("www.test.lab")
assert ans == "203.0.113.11", (ans, status)
lab.stop_lab()
print("  engine flow OK")

print("DRCP GUI SMOKE TEST PASSED")
