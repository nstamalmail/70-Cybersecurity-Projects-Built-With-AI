"""Smoke test: NTAM discovery engine, GUI, sample import, reports."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src", "ntam"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("NTAM_DATA", os.path.abspath(os.path.join(HERE, "..", "test_out")))

import reporting
from engine import DiscoveryController, _arp_table, _ping, topology_from_dict

os.makedirs(os.environ["NTAM_DATA"], exist_ok=True)

# 1) Unit: ping loopback, ARP table read
ok, ttl = _ping("127.0.0.1", 1.0)
assert ok, "loopback ping failed"
arp = _arp_table()
print(f"  ping OK (ttl={ttl}), arp entries: {len(arp)}")

# 2) Discovery on a tiny scope: 127.0.0.1 only (loopback /32 via /30 style scope)
ctrl = DiscoveryController()
result = {}
ctrl.start(
    {"scan_scope": "127.0.0.0/30", "seed_ip": "127.0.0.1", "timeout": 1.0,
     "max_hosts": 8, "snmp": {"enabled": False}, "traceroute": False, "max_hops": 4},
    on_progress=lambda d, t, l: None,
    on_result=lambda dev: result.setdefault("devices", []).append(dev),
    on_done=lambda topo, err: result.update(topo=topo, err=err),
)
t0 = time.time()
while "topo" not in result and time.time() - t0 < 60:
    time.sleep(0.2)
assert result.get("err") is None, result.get("err")
topo = result["topo"]
assert topo is not None and len(topo.devices) >= 1, "loopback should be discovered"
print(f"  discovery OK: {len(topo.devices)} device(s) in {topo.discovery_duration:.1f}s")

# 3) Reports from discovery + DOT
for fmt in ("txt", "json", "csv", "html", "pdf", "dot"):
    out = reporting.export(topo, fmt, os.path.join(os.environ["NTAM_DATA"], f"ntam.{fmt}"))
    size = os.path.getsize(out)
    assert size > 100, (fmt, size)
    print(f"  report {fmt}: {size} bytes")

# 4) Sample import + reports
import json
raw = json.load(open(os.path.join(HERE, "..", "sample_data", "topology_small_office.json"),
                     encoding="utf-8"))
topo2 = topology_from_dict(raw)
assert len(topo2.devices) == 10, len(topo2.devices)
assert len(topo2.links) == 9
for fmt in ("pdf", "html", "dot"):
    out = reporting.export(topo2, fmt, os.path.join(os.environ["NTAM_DATA"], f"ntam_sample.{fmt}"))
    assert os.path.getsize(out) > 300
dot = reporting.to_dot(topo2)
assert "graph topology" in dot and "n0" in dot and "--" in dot
print(f"  sample import OK: {len(topo2.devices)} devices, DOT graph generated")

# 5) GUI construct
from PySide6.QtWidgets import QApplication
app = QApplication(sys.argv)
import theme
import main as m
app.setStyleSheet(theme.STYLESHEET)
win = m.MainWindow()
assert win.inv_tbl.columnCount() == 6
win.topology = topo2
for dev in topo2.devices:
    win._apply_device(dev)
assert win.inv_tbl.rowCount() == 10
win.graph.set_topology(topo2.devices, topo2.links)
assert len(win.graph.nodes) == 10 and len(win.graph.edges) == 9
print("  GUI OK")

print("NTAM SMOKE TEST PASSED")
