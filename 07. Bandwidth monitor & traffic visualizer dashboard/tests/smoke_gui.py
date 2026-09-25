"""Smoke test: BMTVD poller, GUI, sample import, reports."""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src", "bmtvd"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BMTVD_DATA", os.path.abspath(os.path.join(HERE, "..", "test_out")))

import reporting
from engine import AlertEngine, Poller, import_history

os.makedirs(os.environ["BMTVD_DATA"], exist_ok=True)

# 1) Poller: collect two real snapshots quickly
snaps = []
poller = Poller(interval=0.5, on_snapshot=snaps.append)
poller.start()
time.sleep(1.6)
poller.stop()
assert len(snaps) >= 2, f"expected >=2 snapshots, got {len(snaps)}"
snap = snaps[-1]
assert snap.total_download_bps >= 0 and snap.interfaces, "snapshot fields"
print(f"  poller OK: {len(snaps)} snapshots, {len(snap.interfaces)} interfaces, "
      f"{snap.connection_count} connections")

# 2) Alert engine
fired = []
ae = AlertEngine(on_alert=lambda msg, level: fired.append(msg), cooldown=0)
snap2 = snaps[-1]
ae.add_rule("*total*", 0.000001, "down")   # absurdly low threshold -> fires
ae.evaluate(snap2)
assert fired, "alert rule should fire"
print(f"  alert engine OK: '{fired[0][:60]}...'")

# 3) Convert snapshots to history records & export reports
records = []
for s in snaps:
    records.append({
        "timestamp": s.timestamp.isoformat(timespec="seconds"),
        "total_upload_bps": s.total_upload_bps,
        "total_download_bps": s.total_download_bps,
        "connection_count": s.connection_count,
        "interfaces": {n: {"bytes_sent": i.bytes_sent, "bytes_recv": i.bytes_recv,
                           "packets_sent": i.packets_sent, "packets_recv": i.packets_recv,
                           "errors_in": i.errors_in, "errors_out": i.errors_out,
                           "drops_in": i.drops_in, "drops_out": i.drops_out}
                       for n, i in s.interfaces.items()},
        "interface_rates": {n: {"up": r[0], "down": r[1]} for n, r in s.interface_rates.items()},
        "processes": [{"pid": p.pid, "name": p.name, "upload_bps": p.upload_bps,
                       "download_bps": p.download_bps, "connection_count": p.connection_count}
                      for p in s.processes],
    })
period = (records[0]["timestamp"], records[-1]["timestamp"])
alerts = [{"ts": "now", "msg": "test alert"}]
system = "test system"
session = (period, records, alerts, system)
for fmt in ("txt", "json", "csv", "html", "pdf"):
    out = reporting.export(session, fmt, os.path.join(os.environ["BMTVD_DATA"], f"bmtvd.{fmt}"))
    size = os.path.getsize(out)
    assert size > 200, (fmt, size)
    print(f"  report {fmt}: {size} bytes")

# 4) Sample import
sample_path = os.path.join(HERE, "..", "sample_data", "history_workday.json")
snaps2 = import_history(sample_path)
assert len(snaps2) == 8, len(snaps2)
sess2 = (period, snaps2, [{"ts": "2026-09-19T14:03:10", "msg": "sample alert"}], "sample")
for fmt in ("pdf", "html"):
    out = reporting.export(sess2, fmt, os.path.join(os.environ["BMTVD_DATA"], f"bmtvd_sample.{fmt}"))
    assert os.path.getsize(out) > 300
print(f"  sample import OK: {len(snaps2)} snapshots")

# 5) GUI construct
from PySide6.QtWidgets import QApplication
app = QApplication(sys.argv)
import theme
import main as m
app.setStyleSheet(theme.STYLESHEET)
win = m.MainWindow()
assert win.proc_tbl.columnCount() == 6
assert win.iface_tbl.columnCount() == 6
# feed a record through the UI path
win._apply_record(records[-1])
assert win.chart.down, "chart received data"
# import sample through UI loader
win.history = list(snaps2)
win.hist_chart.load_series([s.get("total_upload_bps", 0) for s in snaps2],
                           [s.get("total_download_bps", 0) for s in snaps2])
assert len(win.hist_chart.down) == 8
print("  GUI OK")

print("BMTVD SMOKE TEST PASSED")
