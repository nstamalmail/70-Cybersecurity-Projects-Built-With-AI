"""Report export engine for BMTVD: JSON/CSV/HTML/PDF bandwidth reports."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _fmt(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report(period, snapshots, alerts, system) -> dict:
    total_up = total_down = 0.0
    peak_up = peak_down = 0.0
    peak_time = ""
    proc_totals: dict[str, dict] = {}
    iface_totals: dict[str, dict] = {}
    for s in snapshots:
        total_up += s.get("total_upload_bps", 0)
        total_down += s.get("total_download_bps", 0)
        if s.get("total_download_bps", 0) > peak_down:
            peak_down = s["total_download_bps"]
            peak_time = str(s.get("timestamp", ""))
        if s.get("total_upload_bps", 0) > peak_up:
            peak_up = s["total_upload_bps"]
            peak_time = str(s.get("timestamp", ""))
        for p in s.get("processes", []):
            name = p.get("name") if isinstance(p, dict) else p.name
            pid = p.get("pid") if isinstance(p, dict) else p.pid
            conns = p.get("connection_count", 0) if isinstance(p, dict) else p.connection_count
            key = f"{name} ({pid})"
            entry = proc_totals.setdefault(key, {"name": key, "samples": 0, "peak_rate": 0.0})
            entry["samples"] += 1
            rate = (p.get("upload_bps", 0) + p.get("download_bps", 0)
                    if isinstance(p, dict) else p.upload_bps + p.download_bps)
            entry["peak_rate"] = max(entry["peak_rate"], rate)
        for iname, iface in (s.get("interfaces") or {}).items():
            entry = iface_totals.setdefault(iname, {"name": iname, "sent": 0, "recv": 0})
            if isinstance(iface, dict):
                entry["sent"] = max(entry["sent"], iface.get("bytes_sent", 0))
                entry["recv"] = max(entry["recv"], iface.get("bytes_recv", 0))
    avg_up = total_up / len(snapshots) if snapshots else 0
    avg_down = total_down / len(snapshots) if snapshots else 0
    top = sorted(proc_totals.values(), key=lambda d: -d["peak_rate"])[:15]
    return {
        "title": "Bandwidth Monitor Report",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "period_start": snapshots[0].get("timestamp") if snapshots else period[0],
        "period_end": snapshots[-1].get("timestamp") if snapshots else period[1],
        "snapshot_count": len(snapshots),
        "total_up": total_up, "total_down": total_down,
        "avg_up": avg_up, "avg_down": avg_down,
        "peak_up": peak_up, "peak_down": peak_down, "peak_time": peak_time,
        "top_processes": top,
        "interfaces": sorted(iface_totals.values(), key=lambda d: d["name"]),
        "alerts": list(alerts),
        "system": system,
        "snapshots": list(snapshots),
    }


def to_json(s) -> str:
    payload = build_report(*s)
    return json.dumps(payload, indent=2, default=str)


def to_csv(s) -> str:
    period, snapshots, alerts, system = s
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "total_upload_bps", "total_download_bps", "connection_count"])
    for snap in snapshots:
        writer.writerow([snap.get("timestamp"), snap.get("total_upload_bps", 0),
                         snap.get("total_download_bps", 0), snap.get("connection_count", 0)])
    return buf.getvalue()


def to_txt(s) -> str:
    period, snapshots, alerts, system = s
    rep = build_report(*s)
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Period     : {rep['period_start']}  ->  {rep['period_end']}",
        f"Snapshots  : {rep['snapshot_count']}",
        f"System     : {system}",
        "",
        "[SUMMARY]",
        f"Total transfer (rate-sum) : up {_fmt(rep['total_up'])} / down {_fmt(rep['total_down'])}",
        f"Average rate per sample   : up {_fmt(rep['avg_up'])}/s, down {_fmt(rep['avg_down'])}/s",
        f"Peak rate                 : down {_fmt(rep['peak_down'])}/s at {rep['peak_time']}",
        "",
        "[TOP PROCESSES (by peak rate)]",
        f"{'PROCESS':<36}{'SAMPLES':<9}{'PEAK RATE':>12}",
        "-" * 60,
    ]
    for p in rep["top_processes"]:
        lines.append(f"{p['name']:<36}{p['samples']:<9}{_fmt(p['peak_rate'])+'/s':>12}")
    if not rep["top_processes"]:
        lines.append("  (no per-process data - run as admin for full visibility)")
    lines += ["", "[INTERFACES (cumulative counters)]"]
    for i in rep["interfaces"]:
        lines.append(f"  {i['name']:<28} sent {_fmt(i['sent']):>10}   recv {_fmt(i['recv']):>10}")
    if alerts:
        lines += ["", "[ALERTS]"]
        for a in alerts:
            lines.append(f"  {a.get('ts', '')} {a.get('msg', '')}")
    lines += [
        "",
        "[METHODOLOGY]",
        "Per-process attribution uses psutil connection counts; byte counts are",
        "estimates (psutil limitation). Run elevated for complete process visibility.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(s) -> str:
    rep = build_report(*s)
    proc_rows = "".join(
        f"<tr><td>{_esc(p['name'])}</td><td>{p['samples']}</td>"
        f"<td>{_fmt(p['peak_rate'])}/s</td></tr>"
        for p in rep["top_processes"]) or "<tr><td colspan='3'>No process data</td></tr>"
    iface_rows = "".join(
        f"<tr><td>{_esc(i['name'])}</td><td>{_fmt(i['sent'])}</td>"
        f"<td>{_fmt(i['recv'])}</td></tr>"
        for i in rep["interfaces"]) or "<tr><td colspan='3'>-</td></tr>"
    alert_rows = "".join(
        f"<tr><td>{_esc(a.get('ts'))}</td><td>{_esc(a.get('msg'))}</td></tr>"
        for a in rep["alerts"]) or "<tr><td colspan='2'>None</td></tr>"
    # sparkline of download rate history
    rates = [x.get("total_download_bps", 0) for x in rep["snapshots"]]
    if rates:
        peak = max(rates) or 1
        bars = "".join(
            f"<div style='flex:1;height:{max(2, int(60 * r / peak))}px;"
            f"background:{theme.ACCENT_DIM};margin:0 1px;border-radius:1px'></div>"
            for r in rates[-120:])
        spark = (f"<div style='display:flex;align-items:flex-end;height:70px;"
                 f"background:#fff;border:1px solid #d8dde8;border-radius:6px;padding:4px'>"
                 f"{bars}</div>")
    else:
        spark = "<p>No history samples</p>"
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
.card .num {{ font-size: 22px; font-weight: bold; color: {theme.ACCENT_DIM}; }}
</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">{rep['period_start']} &rarr; {rep['period_end']} &middot;
{rep['snapshot_count']} snapshots &middot; {_esc(rep['system'])}</p>
<div class="cards">
<div class="card"><div class="num">{_fmt(rep['avg_down'])}/s</div>avg download</div>
<div class="card"><div class="num">{_fmt(rep['avg_up'])}/s</div>avg upload</div>
<div class="card"><div class="num">{_fmt(rep['peak_down'])}/s</div>peak download</div>
<div class="card"><div class="num">{len(rep['alerts'])}</div>alerts</div>
</div>
<h2>Download Rate History</h2>
{spark}
<h2>Top Processes</h2>
<table><tr><th>Process</th><th>Samples</th><th>Peak Rate</th></tr>{proc_rows}</table>
<h2>Interfaces</h2>
<table><tr><th>Interface</th><th>Bytes Sent</th><th>Bytes Recv</th></tr>{iface_rows}</table>
<h2>Alerts</h2>
<table><tr><th>Time</th><th>Alert</th></tr>{alert_rows}</table>
<p class="meta">Per-process attribution is connection-count based (psutil limitation).
Generated by BMTVD &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""


def to_pdf(s, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    period, snapshots, alerts, system = s
    rep = build_report(*s)
    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)
    story = [
        Paragraph(rep["title"], styles["Title"]),
        Paragraph(f"{rep['period_start']} &rarr; {rep['period_end']} - "
                  f"{rep['snapshot_count']} snapshots - {system}", styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>Summary:</b> average down {_fmt(rep['avg_down'])}/s, "
                  f"average up {_fmt(rep['avg_up'])}/s, peak down {_fmt(rep['peak_down'])}/s "
                  f"at {rep['peak_time']}. {len(rep['alerts'])} alert(s) fired.", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Top Processes (by peak rate)", styles["Heading2"]),
    ]
    rows = [["Process", "Samples", "Peak rate"]]
    for p in rep["top_processes"][:15]:
        rows.append([str(p["name"])[:45], str(p["samples"]), _fmt(p["peak_rate"]) + "/s"])
    if len(rows) == 1:
        rows.append(["-", "-", "no per-process data"])
    tbl = Table(rows, repeatRows=1, colWidths=[95 * mm, 30 * mm, 50 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Interfaces (cumulative counters)", styles["Heading2"]))
    irows = [["Interface", "Sent", "Received"]]
    for i in rep["interfaces"][:15]:
        irows.append([str(i["name"])[:30], _fmt(i["sent"]), _fmt(i["recv"])])
    if len(irows) == 1:
        irows.append(["-", "-", "-"])
    itbl = Table(irows, repeatRows=1, colWidths=[80 * mm, 47 * mm, 48 * mm])
    itbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(itbl)
    story.append(Spacer(1, 4 * mm))
    if alerts:
        story.append(Paragraph("Alerts", styles["Heading2"]))
        arows = [["Time", "Alert"]]
        for a in alerts[:20]:
            arows.append([str(a.get("ts", "")), str(a.get("msg", ""))[:80]])
        atbl = Table(arows, repeatRows=1, colWidths=[40 * mm, 135 * mm])
        atbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), accent),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ]))
        story.append(atbl)
        story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Per-process attribution uses psutil connection counts; byte counts are estimates "
        "(psutil reports disk I/O per process, not network I/O). Run elevated for complete "
        "process visibility.", styles["Normal"]))
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
