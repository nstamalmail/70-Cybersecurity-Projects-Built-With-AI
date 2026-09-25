"""Report export engine for MMPS: TXT, JSON, CSV, HTML, PDF from the same scan model."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme

REPORT_CSS = f"""
body {{ font-family: 'Segoe UI', sans-serif; background: #f5f6fa; color: #1e2430; margin: 32px; }}
h1 {{ color: {theme.ACCENT_DIM}; border-bottom: 3px solid {theme.ACCENT_DIM}; padding-bottom: 6px; }}
h2 {{ color: {theme.ACCENT_DIM}; margin-top: 28px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; background: #fff; }}
th {{ background: {theme.ACCENT_DIM}; color: #fff; padding: 8px 10px; text-align: left; }}
td {{ border: 1px solid #d8dde8; padding: 6px 10px; }}
tr:nth-child(even) {{ background: #eef1f7; }}
.badge {{ padding: 2px 10px; border-radius: 10px; font-size: 12px; font-weight: bold; color: #fff; }}
.open {{ background: {theme.GREEN}; }}
.closed {{ background: {theme.GRAY}; }}
.filtered {{ background: {theme.ORANGE}; }}
.meta {{ color: #5a6272; font-size: 13px; }}
code, pre {{ background: #eef1f7; border-radius: 4px; padding: 2px 6px; font-family: Consolas, monospace; }}
.note {{ background: #fff8e1; border-left: 4px solid {theme.YELLOW}; padding: 10px 14px; border-radius: 4px; }}
"""


def _esc(value) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_report(result) -> dict:
    """Build the canonical report sections dict from a ScanResult."""
    open_ports = [p for p in result.ports if p.state == "OPEN"]
    risk = [p for p in result.ports if p.risk_level not in ("info", "low")]
    return {
        "title": "Port Scan Report",
        "scan_id": result.scan_id,
        "target": result.target,
        "resolved_ip": result.resolved_ip,
        "scan_mode": result.scan_mode,
        "timestamp": result.timestamp.isoformat(timespec="seconds"),
        "total_scanned": result.total_scanned,
        "open_count": result.open_count,
        "duration_seconds": round(result.duration_seconds, 2),
        "os_fingerprint": result.os_fingerprint,
        "open_ports": open_ports,
        "risk_findings": risk,
    }


def to_txt(result) -> str:
    rep = build_report(result)
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Scan ID        : {rep['scan_id']}",
        f"Target         : {rep['target']}  (resolved: {rep['resolved_ip']})",
        f"Scan mode      : {rep['scan_mode']}",
        f"Date           : {rep['timestamp']}",
        f"OS fingerprint : {rep['os_fingerprint'] or 'n/a (TTL-based)'}",
        f"Ports scanned  : {rep['total_scanned']}   Open: {rep['open_count']}   "
        f"Duration: {rep['duration_seconds']}s",
        "",
        "[OPEN PORTS]",
        f"{'PORT':<9}{'STATE':<10}{'SERVICE':<14}{'VERSION':<28}RISK",
        "-" * 78,
    ]
    for p in rep["open_ports"]:
        version = (p.version or p.banner or "")[:26].replace("\n", " ")
        lines.append(f"{p.port:<9}{p.state:<10}{(p.service or '?'):<14}{version:<28}{p.risk_level}")
    if not rep["open_ports"]:
        lines.append("  (no open ports found)")
    if rep["risk_findings"]:
        lines += ["", "[CRITICAL / HIGH / MEDIUM FINDINGS]"]
        for p in rep["risk_findings"]:
            lines.append(f"- Port {p.port}: {(p.service or '?')} {p.version or ''} ({p.risk_level})")
            for cve in p.cves:
                lines.append(f"    {cve}")
        lines += ["", "[NEXT STEPS]"]
        for p in rep["open_ports"]:
            if p.next_steps:
                for step in p.next_steps:
                    lines.append(f"- {step}")
    lines += [
        "",
        "[METHODOLOGY]",
        f"Technique: {rep['scan_mode']}. TCP Connect completes the handshake (logged by target).",
        "SYN scan sends only SYN; filtered state is ambiguous (firewall drop vs no response).",
        "Service versions come from banner grabbing / probes and may be inaccurate.",
        "",
        "Authorized scanning only - scanning systems without permission is illegal.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_json(result) -> str:
    rep = build_report(result)
    payload = dict(rep)
    payload["open_ports"] = [
        {
            "port": p.port,
            "state": p.state,
            "service": p.service,
            "version": p.version,
            "banner": p.banner,
            "cves": p.cves,
            "risk_level": p.risk_level,
            "next_steps": p.next_steps,
        }
        for p in rep["open_ports"]
    ]
    payload["risk_findings"] = [
        {"port": p.port, "service": p.service, "version": p.version,
         "risk": p.risk_level, "cves": p.cves}
        for p in rep["risk_findings"]
    ]
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2, default=str)


def to_csv(result) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["port", "state", "service", "version", "banner", "risk_level", "cves"])
    for p in result.ports:
        writer.writerow([
            p.port, p.state, p.service or "", (p.version or p.banner or "").strip(),
            (p.banner or "").strip()[:200], p.risk_level, ";".join(p.cves),
        ])
    return buf.getvalue()


def to_html(result) -> str:
    rep = build_report(result)
    rows = []
    for p in rep["open_ports"]:
        rows.append(
            f"<tr><td><b>{p.port}</b>/tcp</td>"
            f"<td><span class='badge {p.state.lower()}'>{p.state}</span></td>"
            f"<td>{_esc(p.service or '?')}</td>"
            f"<td><code>{_esc((p.version or p.banner or '')[:60])}</code></td>"
            f"<td>{p.risk_level}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5'>No open ports found</td></tr>")
    risk_rows = []
    for p in rep["risk_findings"]:
        risk_rows.append(
            f"<tr><td>{p.port}</td><td>{_esc(p.service or '?')}</td>"
            f"<td>{_esc(p.version or '')}</td><td><b>{p.risk_level}</b></td>"
            f"<td>{_esc(', '.join(p.cves)) or '-'}</td></tr>"
        )
    if not risk_rows:
        risk_rows.append("<tr><td colspan='5'>No significant risk findings</td></tr>")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{rep['title']}</title>
<style>{REPORT_CSS}</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">Scan ID <b>{rep['scan_id']}</b> &middot; Target <b>{_esc(rep['target'])}</b>
(&rarr; {_esc(rep['resolved_ip'])}) &middot; Mode <b>{rep['scan_mode']}</b> &middot; {rep['timestamp']}</p>
<div class="note">Authorized scanning only &mdash; scanning systems without permission is illegal in most jurisdictions.</div>
<h2>Executive Summary</h2>
<table>
<tr><th>Ports scanned</th><th>Open ports</th><th>Duration</th><th>OS fingerprint</th></tr>
<tr><td>{rep['total_scanned']}</td><td>{rep['open_count']}</td>
<td>{rep['duration_seconds']}s</td><td>{_esc(rep['os_fingerprint'] or 'n/a')}</td></tr>
</table>
<h2>Open Ports</h2>
<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th><th>Risk</th></tr>
{''.join(rows)}</table>
<h2>Risk Findings</h2>
<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th><th>CVE hints</th></tr>
{''.join(risk_rows)}</table>
<h2>Methodology</h2>
<p>Technique: <b>{rep['scan_mode']}</b>. TCP Connect completes the full three-way handshake and is
logged by the target. SYN scans never complete the handshake but require raw sockets. Filtered
ports are ambiguous (firewall drop vs no response). Versions come from banners and may be
inaccurate &mdash; verify manually.</p>
<p class="meta">Generated by MMPS &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""
    return html


def to_pdf(result, path: str) -> str:
    """Render a PDF report with reportlab; returns the written path."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    rep = build_report(result)
    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm,
    )
    story = [
        Paragraph(rep["title"], styles["Title"]),
        Paragraph(
            f"Scan ID {rep['scan_id']} &middot; Target {rep['target']} "
            f"(&rarr; {rep['resolved_ip']}) &middot; Mode {rep['scan_mode']} "
            f"&middot; {rep['timestamp']}",
            styles["Normal"],
        ),
        Spacer(1, 6 * mm),
        Paragraph("Executive Summary", styles["Heading2"]),
        Table(
            [["Ports scanned", "Open ports", "Duration", "OS fingerprint"],
             [str(rep["total_scanned"]), str(rep["open_count"]),
              f"{rep['duration_seconds']}s", rep["os_fingerprint"] or "n/a"]],
            colWidths=[45 * mm, 45 * mm, 45 * mm, 45 * mm],
        ),
        Spacer(1, 6 * mm),
        Paragraph("Open Ports", styles["Heading2"]),
    ]
    port_rows = [["Port", "State", "Service", "Version / Banner", "Risk"]]
    for p in rep["open_ports"]:
        port_rows.append([
            str(p.port), p.state, p.service or "?",
            (p.version or p.banner or "").strip()[:48] or "-", p.risk_level,
        ])
    if len(port_rows) == 1:
        port_rows.append(["-", "-", "-", "No open ports found", "-"])
    tbl = Table(port_rows, repeatRows=1, colWidths=[20 * mm, 22 * mm, 30 * mm, 78 * mm, 28 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Risk Findings", styles["Heading2"]))
    risk_rows = [["Port", "Service", "Version", "Risk", "CVE hints"]]
    for p in rep["risk_findings"]:
        risk_rows.append([str(p.port), p.service or "?", p.version or "",
                          p.risk_level, ", ".join(p.cves) or "-"])
    if len(risk_rows) == 1:
        risk_rows.append(["-", "-", "-", "-", "No significant risk findings"])
    rtbl = Table(risk_rows, repeatRows=1, colWidths=[18 * mm, 30 * mm, 46 * mm, 24 * mm, 60 * mm])
    rtbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(rtbl)
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Methodology & Disclaimer", styles["Heading2"]))
    story.append(Paragraph(
        f"Technique: {rep['scan_mode']}. TCP Connect completes the full three-way handshake and is "
        "logged by the target; SYN scans never complete the handshake but require raw sockets. "
        "Filtered ports are ambiguous (firewall drop vs no response). Versions come from banners "
        "and may be inaccurate. Authorized scanning only - scanning systems without permission "
        "is illegal in most jurisdictions.",
        styles["Normal"],
    ))
    doc.build(story)
    return path


def export(result, fmt: str, path: str) -> str:
    """Export a scan result in the requested format. Returns written path."""
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_txt(result))
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(result))
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(result))
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(result))
    elif fmt == "pdf":
        to_pdf(result, path)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return path
