# WGTB Memory: decisions & lessons

- The `cryptography` library's X25519PrivateKey.generate() + base64 encoding produces
  exactly WireGuard's key format; no shelling out to `wg genkey` (keeps the exe
  portable and works without WireGuard installed).
- QPixmap.loadFromData fails silently in offscreen/CI environments sometimes; the QR
  smoke test checks PNG magic bytes of the encoded buffer instead of pixmap.isNull().
- After populating a table in _refresh, select row 0 explicitly - preview panes
  (QR/config) otherwise sit empty with currentRow() == -1 and smoke tests "fail" with
  no actual bug.
- wg-quick config rendering is pure string templating from a TunnelSpec dataclass;
  peers and server each render independently so import -> re-export is byte-stable.
- QR codes encode the client config text; error correction level M keeps them scannable
  at the size a phone camera expects for a ~400-char payload.
- Reports flag PRIVATE KEY material and never include preshared keys in the CSV/HTML
  summaries - only in the explicitly requested client config exports.
