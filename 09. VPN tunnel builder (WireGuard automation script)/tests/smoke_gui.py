"""Smoke test: WGTB engine (keys, configs, peers), GUI, sample import, reports."""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src", "wgtb"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("WGTB_DATA", os.path.abspath(os.path.join(HERE, "..", "test_out")))

import reporting
import engine
from engine import (
    add_peer, create_session, generate_keypair, generate_peer_conf,
    generate_server_conf, key_fingerprint, parse_wg_show, session_from_dict,
)

os.makedirs(os.environ["WGTB_DATA"], exist_ok=True)

# 1) Key generation: base64, 32 bytes, clamped
priv, pub = generate_keypair()
assert len(base64.b64decode(priv)) == 32 and len(base64.b64decode(pub)) == 32
priv_raw = base64.b64decode(priv)
assert priv_raw[0] & 7 == 0, "first byte must be clamped (& 248)"
assert priv_raw[31] & 128 == 0, "last byte high bit must be clear"
assert priv_raw[31] & 64, "last byte must set bit 6"
assert key_fingerprint(pub) != pub
print("  key generation OK (clamped curve25519)")

# 2) Session + peers
sess = create_session("wg0", "10.0.0.0/24", 51820, "10.0.0.1")
assert sess.server_ip == "10.0.0.1"
p1 = add_peer(sess, "laptop", with_psk=True)
p2 = add_peer(sess, "phone", with_psk=True)
p3 = add_peer(sess, "branch", with_psk=False, allowed_ips="192.168.20.0/24")
assert [p.assigned_ip for p in (p1, p2, p3)] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
assert p1.preshared_key and p3.preshared_key is None
print("  session + peers OK:", [(p.name, p.assigned_ip) for p in sess.peers])

# 3) Config generation
sconf = generate_server_conf(sess)
assert "[Interface]" in sconf and "ListenPort = 51820" in sconf
assert "PublicKey = " + p1.public_key in sconf
assert sconf.count("[Peer]") == 3
pconf = generate_peer_conf(sess, p1)
assert f"PrivateKey = {p1.private_key}" in pconf
assert "Endpoint = <SERVER_PUBLIC_IP>:51820" in pconf
print("  server + peer configs OK")

# 4) wg show parser (static sample)
sample_show = """
interface: wg0
  public key: ABC=
  listening port: 51820

peer: DEF=
  endpoint: 203.0.113.7:41820
  allowed ips: 10.0.0.2/32
  latest handshake: 1 minute, 2 seconds ago
  transfer: 1.5 MiB received, 4.2 MiB sent
"""
peers = parse_wg_show(sample_show)
assert len(peers) == 1
assert peers[0]["public_key"] == "DEF="
assert "1 minute" in peers[0]["handshake"]
assert "1.5 MiB" in peers[0]["transfer_rx"]
print("  wg show parser OK")

# 5) Reports
for fmt in ("txt", "json", "csv", "html", "pdf"):
    out = reporting.export(sess, fmt, os.path.join(os.environ["WGTB_DATA"], f"wgtb.{fmt}"))
    size = os.path.getsize(out)
    assert size > 300, (fmt, size)
    print(f"  report {fmt}: {size} bytes")
# reports must NOT contain private keys
with open(os.path.join(os.environ["WGTB_DATA"], "wgtb.json"), encoding="utf-8") as fh:
    assert p1.private_key not in fh.read(), "private key leaked into report!"
print("  no private keys in reports OK")

# 6) Sample import
import json
raw = json.load(open(os.path.join(HERE, "..", "sample_data", "tunnel_branch_office.json"),
                     encoding="utf-8"))
sess2 = session_from_dict(raw)
assert len(sess2.peers) == 3 and sess2.listen_port == 51820
out = reporting.export(sess2, "pdf", os.path.join(os.environ["WGTB_DATA"], "wgtb_sample.pdf"))
assert os.path.getsize(out) > 400
print(f"  sample import OK: {len(sess2.peers)} peers")

# 7) QR generation
qr_out = engine.qr_png_path(generate_peer_conf(sess2, sess2.peers[0]),
                            os.path.join(os.environ["WGTB_DATA"], "sample_qr.png"))
assert os.path.getsize(qr_out) > 200
print("  QR PNG OK")

# 8) GUI construct
from PySide6.QtWidgets import QApplication
app = QApplication(sys.argv)
import theme
import main as m
app.setStyleSheet(theme.STYLESHEET)
win = m.MainWindow()
assert win.peer_tbl.columnCount() == 5
win.session = sess2
win._refresh()
assert win.peer_tbl.rowCount() == 3
assert win.qr_label.pixmap() is not None and not win.qr_label.pixmap().isNull()
print("  GUI OK (with QR render)")

print("WGTB SMOKE TEST PASSED")
