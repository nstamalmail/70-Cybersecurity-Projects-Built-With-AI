"""Report export engine for WGTB: JSON/CSV/HTML/PDF/TXT provisioning reports."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report(sess, include_private: bool = False) -> dict:
    d = sess.to_dict(include_private=False)
    d["peer_count"] = len(sess.peers)
    d["psk_enabled"] = sum(1 for p in sess.peers if p.preshared_key)
    d["platform"] = __import__("platform").system()
    return d


def to_json(sess) -> str:
    payload = build_report(sess, include_private=False)
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    payload["security_note"] = ("Private keys are excluded from reports. Export session "
                                "JSON with 'include private keys' only for backup purposes.")
    return json.dumps(payload, indent=2, default=str)


def to_csv(sess) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["peer_name", "assigned_ip", "public_key", "fingerprint",
                     "allowed_ips", "endpoint", "keepalive", "preshared_key"])
    for p in sess.peers:
        writer.writerow([p.name, p.assigned_ip, p.public_key,
                         __import__("engine").key_fingerprint(p.public_key),
                         p.allowed_ips, p.endpoint or "-", p.persistent_keepalive or "-",
                         "yes" if p.preshared_key else "no"])
    return buf.getvalue()


def to_txt(sess) -> str:
    lines = [
        "=" * 70,
        "  WireGuard Tunnel Provisioning Report",
        "=" * 70,
        f"Session      : {sess.session_id}",
        f"Interface    : {sess.interface_name}",
        f"Server IP    : {sess.server_ip}/{sess.server_network.split('/')[-1]}",
        f"Listen port  : {sess.listen_port}",
        f"DNS          : {sess.dns}",
        f"Server pubkey: {sess.server_public_key}",
        f"Fingerprint  : {__import__('engine').key_fingerprint(sess.server_public_key)}",
        f"Peers        : {len(sess.peers)} "
        f"(PSK enabled on {sum(1 for p in sess.peers if p.preshared_key)})",
        "",
        "[PEERS]",
        f"{'NAME':<14}{'TUNNEL IP':<18}{'ALLOWED':<12}{'FINGERPRINT'}",
        "-" * 70,
    ]
    for p in sess.peers:
        lines.append(f"{p.name:<14}{p.assigned_ip:<18}{p.allowed_ips:<12}"
                     f"{__import__('engine').key_fingerprint(p.public_key)}")
    lines += [
        "",
        "[DEPLOYMENT]",
        "1. Copy the server config to /etc/wireguard/wg0.conf (Linux) or import",
        "   into the WireGuard app (Windows/macOS).",
        "2. Start: sudo wg-quick up wg0   (Linux)  /  install tunnel service (Windows).",
        "3. Distribute peer configs (QR code for mobile) over a SECURE channel.",
        "4. Verify handshakes: wg show",
        "",
        "[SECURITY NOTES]",
        "- Private keys are never included in reports.",
        "- Distribute peer configs over a secure channel; anyone with a config",
        "  can join the tunnel.",
        "- Preshared keys add post-quantum resistance.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(sess) -> str:
    peer_rows = "".join(
        f"<tr><td><b>{_esc(p.name)}</b></td><td><code>{p.assigned_ip}</code></td>"
        f"<td>{_esc(p.allowed_ips)}</td>"
        f"<td><code>{__import__('engine').key_fingerprint(p.public_key)}</code></td>"
        f"<td>{'yes' if p.preshared_key else 'no'}</td></tr>"
        for p in sess.peers)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WireGuard Provisioning Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #f5f6fa; color: #1e2430; margin: 32px; }}
h1 {{ color: {theme.ACCENT_DIM}; border-bottom: 3px solid {theme.ACCENT_DIM}; padding-bottom: 6px; }}
h2 {{ color: {theme.ACCENT_DIM}; margin-top: 28px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; background: #fff; }}
th {{ background: {theme.ACCENT_DIM}; color: #fff; padding: 8px 10px; text-align: left; }}
td {{ border: 1px solid #d8dde8; padding: 6px 10px; }}
tr:nth-child(even) {{ background: #eef1f7; }}
code, pre {{ background: #eef1f7; border-radius: 4px; padding: 2px 6px; font-family: Consolas, monospace; }}
pre {{ padding: 12px; overflow-x: auto; }}
.meta {{ color: #5a6272; font-size: 13px; }}
.cards {{ display: flex; gap: 14px; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #d8dde8; border-radius: 8px; padding: 14px 20px;
         flex: 1; text-align: center; }}
.card .num {{ font-size: 24px; font-weight: bold; color: {theme.ACCENT_DIM}; }}
.note {{ background: #fdecea; border-left: 4px solid {theme.RED}; padding: 10px 14px; }}
</style></head><body>
<h1>WireGuard Tunnel Provisioning Report</h1>
<p class="meta">Session {sess.session_id} &middot; {sess.created_at.isoformat(timespec='seconds')}
&middot; interface {_esc(sess.interface_name)} &middot; port {sess.listen_port}</p>
<div class="cards">
<div class="card"><div class="num">{len(sess.peers)}</div>peers</div>
<div class="card"><div class="num">{sum(1 for p in sess.peers if p.preshared_key)}</div>with PSK</div>
<div class="card"><div class="num">{_esc(sess.server_network)}</div>tunnel network</div>
</div>
<h2>Server</h2>
<p>Public key: <code>{sess.server_public_key}</code><br>
Fingerprint: <code>{__import__('engine').key_fingerprint(sess.server_public_key)}</code><br>
Tunnel IP: <code>{sess.server_ip}</code> &middot; Listen: <code>{sess.listen_port}/udp</code></p>
<h2>Peers</h2>
<table><tr><th>Name</th><th>Tunnel IP</th><th>Allowed IPs</th><th>Key Fingerprint</th><th>PSK</th></tr>
{peer_rows}</table>
<h2>Server Config Preview</h2>
<pre>{_esc(__import__('engine').generate_server_conf(sess))}</pre>
<div class="note"><b>Security:</b> private keys are excluded from reports. Distribute peer
configs over a secure channel - anyone holding a config can join the tunnel.</div>
<p class="meta">Generated by WGTB &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""


def to_pdf(sess, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)
    story = [
        Paragraph("WireGuard Tunnel Provisioning Report", styles["Title"]),
        Paragraph(f"Session {sess.session_id} - {sess.created_at.isoformat(timespec='seconds')} "
                  f"- interface {sess.interface_name} - port {sess.listen_port}/udp",
                  styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>Server:</b> {sess.server_ip}/{sess.server_network.split('/')[-1]} - "
                  f"public key fingerprint "
                  f"{__import__('engine').key_fingerprint(sess.server_public_key)}", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Peers", styles["Heading2"]),
    ]
    rows = [["Name", "Tunnel IP", "Allowed IPs", "Fingerprint", "PSK"]]
    for p in sess.peers:
        rows.append([p.name, p.assigned_ip, p.allowed_ips,
                     __import__("engine").key_fingerprint(p.public_key),
                     "yes" if p.preshared_key else "no"])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "-", "-"])
    tbl = Table(rows, repeatRows=1, colWidths=[30 * mm, 30 * mm, 30 * mm, 60 * mm, 18 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Server Config", styles["Heading2"]))
    story.append(Preformatted(__import__("engine").generate_server_conf(sess),
                              styles["Code"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Security Notes", styles["Heading2"]))
    story.append(Paragraph(
        "Private keys are never included in reports. Distribute peer configs over a "
        "secure channel; anyone with a config can join the tunnel. Preshared keys add a "
        "post-quantum resistance layer. Verify handshakes with 'wg show' after deployment.",
        styles["Normal"]))
    doc.build(story)
    return path


def export(sess, fmt: str, path: str) -> str:
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_txt(sess))
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(sess))
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(sess))
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(sess))
    elif fmt == "pdf":
        to_pdf(sess, path)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return path
