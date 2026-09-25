"""Report export engine for CPS: JSON/CSV/HTML/PDF proxy traffic reports."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report(s) -> dict:
    return {
        "title": "Proxy Traffic Report",
        "session_id": s.session_id,
        "timestamp": s.timestamp.isoformat(timespec="seconds"),
        "config": s.config,
        "total_connections": s.total_connections,
        "total_bytes_up": s.total_bytes_up,
        "total_bytes_down": s.total_bytes_down,
        "total_bytes": s.total_bytes_up + s.total_bytes_down,
        "blocked_count": s.blocked_count,
        "error_count": s.error_count,
        "auth_fail_count": s.auth_fail_count,
        "unique_destinations": s.unique_destinations,
        "top_destinations": s.top_destinations,
        "top_clients": s.top_clients,
        "blocked": s.blocked,
        "errors": s.errors,
        "traffic": s.traffic,
    }


def to_json(s) -> str:
    payload = build_report(s)
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2, default=str)


def to_csv(s) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    rep = build_report(s)
    writer.writerow(["timestamp", "client_ip", "dest_host", "dest_port", "protocol",
                     "bytes_up", "bytes_down", "duration_ms", "status", "detail"])
    for r in rep["traffic"]:
        writer.writerow([r.get("timestamp"), r.get("client_ip"), r.get("dest_host"),
                         r.get("dest_port"), r.get("protocol"), r.get("bytes_up"),
                         r.get("bytes_down"), r.get("duration_ms"), r.get("status"),
                         r.get("detail")])
    return buf.getvalue()


def to_txt(s) -> str:
    rep = build_report(s)
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Session   : {rep['session_id']}",
        f"Generated : {rep['timestamp']}",
        f"Server    : {rep['config'].get('listen_host')}:{rep['config'].get('listen_port')}"
        f" ({rep['config'].get('protocol_mode')})",
        "",
        "[SUMMARY]",
        f"Total connections : {rep['total_connections']}",
        f"Bytes up          : {_fmt_bytes(rep['total_bytes_up'])}",
        f"Bytes down        : {_fmt_bytes(rep['total_bytes_down'])}",
        f"Unique destinations: {rep['unique_destinations']}",
        f"Blocked           : {rep['blocked_count']}  Errors: {rep['error_count']}"
        f"  Auth failures: {rep['auth_fail_count']}",
        "",
        "[TOP DESTINATIONS]",
        f"{'DESTINATION':<40}{'CONNS':<8}{'BYTES':>12}",
        "-" * 62,
    ]
    for d in rep["top_destinations"]:
        lines.append(f"{d.get('dest', ''):<40}{d.get('count', 0):<8}{_fmt_bytes(d.get('bytes')):>12}")
    if not rep["top_destinations"]:
        lines.append("  (none)")
    lines += ["", "[TOP CLIENTS]"]
    for c in rep["top_clients"]:
        lines.append(f"  {c.get('client')}: {c.get('count')} connections")
    if rep["blocked"]:
        lines += ["", "[BLOCKED CONNECTIONS]"]
        for b in rep["blocked"][:30]:
            lines.append(f"  {b.get('dest_host')}:{b.get('dest_port')} - {b.get('detail')}")
    if rep["errors"]:
        lines += ["", "[ERRORS / AUTH FAILURES]"]
        for e in rep["errors"][:30]:
            lines.append(f"  {e.get('status')}: {e.get('dest_host')} - {e.get('detail')}")
    lines += [
        "",
        "[NOTES]",
        "This proxy tunnels TLS; it does not intercept or inspect encrypted content.",
        "Default bind is loopback - binding to 0.0.0.0 requires authentication.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(s) -> str:
    rep = build_report(s)
    dest_rows = "".join(
        f"<tr><td>{_esc(d.get('dest'))}</td><td>{d.get('count')}</td>"
        f"<td>{_fmt_bytes(d.get('bytes'))}</td></tr>"
        for d in rep["top_destinations"]) or "<tr><td colspan='3'>No traffic</td></tr>"
    client_rows = "".join(
        f"<tr><td>{_esc(c.get('client'))}</td><td>{c.get('count')}</td></tr>"
        for c in rep["top_clients"]) or "<tr><td colspan='2'>No clients</td></tr>"
    blocked_rows = "".join(
        f"<tr><td>{_esc(b.get('dest_host'))}:{b.get('dest_port')}</td>"
        f"<td>{_esc(b.get('detail'))}</td><td>{_esc(b.get('timestamp'))}</td></tr>"
        for b in rep["blocked"][:50]) or "<tr><td colspan='3'>None</td></tr>"
    error_rows = "".join(
        f"<tr><td>{_esc(e.get('status'))}</td><td>{_esc(e.get('dest_host'))}</td>"
        f"<td>{_esc(e.get('detail'))}</td></tr>"
        for e in rep["errors"][:50]) or "<tr><td colspan='3'>None</td></tr>"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{rep['title']}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #f5f6fa; color: #1e2430; margin: 32px; }}
h1 {{ color: {theme.ACCENT_DIM}; border-bottom: 3px solid {theme.ACCENT_DIM}; padding-bottom: 6px; }}
h2 {{ color: {theme.ACCENT_DIM}; margin-top: 28px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; background: #fff; }}
th {{ background: {theme.ACCENT_DIM}; color: #fff; padding: 8px 10px; text-align: left; }}
td {{ border: 1px solid #d8dde8; padding: 6px 10px; }}
tr:nth-child(even) {{ background: #eef1f7; }}
.meta {{ color: #5a6272; font-size: 13px; }}
.cards {{ display: flex; gap: 14px; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #d8dde8; border-radius: 8px; padding: 14px 20px;
         flex: 1; text-align: center; }}
.card .num {{ font-size: 26px; font-weight: bold; color: {theme.ACCENT_DIM}; }}
.note {{ background: #eef4ff; border-left: 4px solid {theme.ACCENT_DIM}; padding: 10px 14px; }}
</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">Session {rep['session_id']} &middot; {rep['timestamp']} &middot; server
{_esc(str(rep['config'].get('listen_host')))}:{rep['config'].get('listen_port')}
({rep['config'].get('protocol_mode')})</p>
<div class="cards">
<div class="card"><div class="num">{rep['total_connections']}</div>connections</div>
<div class="card"><div class="num">{_fmt_bytes(rep['total_bytes'])}</div>transferred</div>
<div class="card"><div class="num">{rep['unique_destinations']}</div>destinations</div>
<div class="card"><div class="num">{rep['blocked_count']}</div>blocked</div>
</div>
<h2>Top Destinations</h2>
<table><tr><th>Destination</th><th>Connections</th><th>Bytes</th></tr>{dest_rows}</table>
<h2>Top Clients</h2>
<table><tr><th>Client IP</th><th>Connections</th></tr>{client_rows}</table>
<h2>Blocked Connections</h2>
<table><tr><th>Destination</th><th>Reason</th><th>Time</th></tr>{blocked_rows}</table>
<h2>Errors / Auth Failures</h2>
<table><tr><th>Status</th><th>Destination</th><th>Detail</th></tr>{error_rows}</table>
<div class="note">This proxy tunnels TLS but never intercepts encrypted content. Reports
contain destination hostnames - store accordingly.</div>
<p class="meta">Generated by CPS &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""


def to_pdf(s, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    rep = build_report(s)
    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)
    story = [
        Paragraph(rep["title"], styles["Title"]),
        Paragraph(f"Session {rep['session_id']} - {rep['timestamp']} - server "
                  f"{rep['config'].get('listen_host')}:{rep['config'].get('listen_port')} "
                  f"({rep['config'].get('protocol_mode')})", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Summary:</b> {rep['total_connections']} connections - "
            f"{_fmt_bytes(rep['total_bytes'])} transferred "
            f"(up {_fmt_bytes(rep['total_bytes_up'])} / down {_fmt_bytes(rep['total_bytes_down'])}) - "
            f"{rep['unique_destinations']} destinations - {rep['blocked_count']} blocked - "
            f"{rep['error_count']} errors - {rep['auth_fail_count']} auth failures",
            styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Top Destinations", styles["Heading2"]),
    ]
    rows = [["Destination", "Connections", "Bytes"]]
    for d in rep["top_destinations"][:15]:
        rows.append([str(d.get("dest")), str(d.get("count")), _fmt_bytes(d.get("bytes"))])
    if len(rows) == 1:
        rows.append(["-", "-", "-"])
    tbl = Table(rows, repeatRows=1, colWidths=[85 * mm, 40 * mm, 50 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Blocked Connections", styles["Heading2"]))
    brows = [["Destination", "Reason", "Time"]]
    for b in rep["blocked"][:20]:
        brows.append([f"{b.get('dest_host')}:{b.get('dest_port')}",
                      str(b.get("detail"))[:60], str(b.get("timestamp"))])
    if len(brows) == 1:
        brows.append(["-", "None", "-"])
    btbl = Table(brows, repeatRows=1, colWidths=[55 * mm, 75 * mm, 45 * mm])
    btbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(btbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Notes", styles["Heading2"]))
    story.append(Paragraph(
        "This proxy tunnels TLS; it does not intercept or inspect encrypted content. "
        "Default bind is loopback; binding to a public interface requires authentication. "
        "Traffic logs contain destination hostnames and client IPs - store accordingly.",
        styles["Normal"]))
    doc.build(story)
    return path


def export(s, fmt: str, path: str) -> str:
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_txt(s))
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(s))
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(s))
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(s))
    elif fmt == "pdf":
        to_pdf(s, path)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return path
