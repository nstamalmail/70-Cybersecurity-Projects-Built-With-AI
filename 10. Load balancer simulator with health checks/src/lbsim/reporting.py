"""Report export engine for LBSim: JSON/CSV/HTML/PDF/TXT simulation reports."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report(sim) -> dict:
    backends = sim.backends if isinstance(sim.backends, list) else []
    total = sim.total_requests or 0
    dist = []
    for b in backends:
        if isinstance(b, dict):
            name, reqs, health = b.get("name"), b.get("total_requests", 0), b.get("health")
            weight, mode = b.get("weight"), b.get("mode")
        else:
            name, reqs, health = b.name, b.total_requests, b.health
            weight, mode = b.weight, b.mode
        pct = (100.0 * reqs / total) if total else 0.0
        dist.append({"name": name, "requests": reqs, "pct": round(pct, 1),
                     "health": health, "weight": weight, "mode": mode})
    transitions = []
    for t in (sim.state_transitions or []):
        if isinstance(t, dict):
            transitions.append(t)
        else:
            transitions.append(vars(t))
    return {
        "title": "Load Balancer Simulation Report",
        "simulation_id": sim.simulation_id,
        "timestamp": sim.timestamp.isoformat(timespec="seconds") if isinstance(sim.timestamp, datetime) else str(sim.timestamp),
        "algorithm": sim.algorithm,
        "health_check_config": sim.health_check_config,
        "duration_seconds": sim.duration_seconds,
        "total_requests": total,
        "distribution": dist,
        "state_transitions": transitions,
        "health_check_log": list(sim.health_check_log or [])[-100:],
    }


def to_json(sim) -> str:
    payload = build_report(sim)
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2, default=str)


def to_csv(sim) -> str:
    rep = build_report(sim)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["backend", "requests", "percent", "final_health", "mode", "weight"])
    for d in rep["distribution"]:
        writer.writerow([d["name"], d["requests"], d["pct"], d["health"], d["mode"], d["weight"]])
    writer.writerow([])
    writer.writerow(["timestamp", "backend", "from_state", "to_state", "reason"])
    for t in rep["state_transitions"]:
        writer.writerow([t.get("timestamp"), t.get("backend"), t.get("from_state"),
                         t.get("to_state"), t.get("reason")])
    return buf.getvalue()


def to_txt(sim) -> str:
    rep = build_report(sim)
    hc = rep["health_check_config"]
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Simulation : {rep['simulation_id']}",
        f"Run at     : {rep['timestamp']}",
        f"Algorithm  : {rep['algorithm']}",
        f"Duration   : {rep['duration_seconds']:.1f}s",
        f"Requests   : {rep['total_requests']}",
        f"Health chk : {hc.get('check_type', '?')} every {hc.get('interval_seconds', '?')}s "
        f"(fall {hc.get('fall_threshold', '?')} / rise {hc.get('rise_threshold', '?')})",
        "",
        "[TRAFFIC DISTRIBUTION]",
        f"{'BACKEND':<18}{'MODE':<14}{'REQUESTS':<10}{'SHARE':<8}{'FINAL STATE'}",
        "-" * 70,
    ]
    for d in rep["distribution"]:
        lines.append(f"{str(d['name']):<18}{str(d['mode']):<14}{d['requests']:<10}"
                     f"{d['pct']:<8}{d['health']}")
    if rep["state_transitions"]:
        lines += ["", "[STATE TRANSITIONS]"]
        for t in rep["state_transitions"][:30]:
            lines.append(f"  {t.get('timestamp')} {t.get('backend')}: "
                         f"{t.get('from_state')} -> {t.get('to_state')} ({t.get('reason')})")
    lines += [
        "",
        "[NOTES]",
        "Simulation only - backends are in-process mocks; no packets were sent.",
        "Round-robin should distribute evenly across equal-weight healthy backends;",
        "weighted WRR scales by weight; least-connections balances active load;",
        "ip-hash gives the same client the same backend (session affinity).",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(sim) -> str:
    rep = build_report(sim)
    hc = rep["health_check_config"]
    total = rep["total_requests"] or 1
    dist_rows = ""
    for d in rep["distribution"]:
        bar_w = int(d["pct"])
        color = theme.GREEN if d["health"] == "UP" else theme.RED
        dist_rows += (f"<tr><td><b>{_esc(d['name'])}</b></td><td>{d['requests']}</td>"
                      f"<td>{d['pct']}%</td>"
                      f"<td><div style='background:{theme.ACCENT_DIM};height:12px;"
                      f"width:{bar_w * 2}px;border-radius:3px'></div></td>"
                      f"<td style='color:{color};font-weight:bold'>{d['health']}</td></tr>")
    trans_rows = "".join(
        f"<tr><td>{_esc(t.get('timestamp'))}</td><td>{_esc(t.get('backend'))}</td>"
        f"<td>{t.get('from_state')} &rarr; <b>{t.get('to_state')}</b></td>"
        f"<td>{_esc(t.get('reason'))}</td></tr>"
        for t in rep["state_transitions"][:30]) or "<tr><td colspan='4'>None</td></tr>"
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
.card .num {{ font-size: 24px; font-weight: bold; color: {theme.ACCENT_DIM}; }}
.note {{ background: #eef4ff; border-left: 4px solid {theme.ACCENT_DIM}; padding: 10px 14px; }}
code {{ background: #eef1f7; padding: 2px 6px; border-radius: 4px; }}
</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">Simulation {rep['simulation_id']} &middot; {rep['timestamp']} &middot;
algorithm <b>{rep['algorithm']}</b> &middot; {rep['duration_seconds']:.1f}s</p>
<div class="cards">
<div class="card"><div class="num">{rep['total_requests']}</div>requests</div>
<div class="card"><div class="num">{len(rep['distribution'])}</div>backends</div>
<div class="card"><div class="num">{len(rep['state_transitions'])}</div>transitions</div>
<div class="card"><div class="num">{hc.get('check_type', '?')}</div>health check</div>
</div>
<h2>Traffic Distribution</h2>
<table><tr><th>Backend</th><th>Requests</th><th>Share</th><th></th><th>Final State</th></tr>
{dist_rows}</table>
<h2>State Transitions</h2>
<table><tr><th>Time</th><th>Backend</th><th>Change</th><th>Reason</th></tr>{trans_rows}</table>
<div class="note">Health check: <code>{hc.get('check_type')}</code> every
<code>{hc.get('interval_seconds')}s</code>, fall <code>{hc.get('fall_threshold')}</code>,
rise <code>{hc.get('rise_threshold')}</code>. Simulation is entirely in-process; no packets
were sent.</div>
<p class="meta">Generated by LBSim &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""


def to_pdf(sim, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    rep = build_report(sim)
    hc = rep["health_check_config"]
    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)
    story = [
        Paragraph(rep["title"], styles["Title"]),
        Paragraph(f"Simulation {rep['simulation_id']} - {rep['timestamp']} - algorithm "
                  f"{rep['algorithm']} - {rep['total_requests']} requests in "
                  f"{rep['duration_seconds']:.1f}s", styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"Health check: {hc.get('check_type')} every {hc.get('interval_seconds')}s, "
                  f"fall {hc.get('fall_threshold')} / rise {hc.get('rise_threshold')}.",
                  styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Traffic Distribution", styles["Heading2"]),
    ]
    rows = [["Backend", "Mode", "Requests", "Share", "Final state"]]
    for d in rep["distribution"]:
        rows.append([str(d["name"]), str(d["mode"]), str(d["requests"]),
                     f"{d['pct']}%", str(d["health"])])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "-", "-"])
    tbl = Table(rows, repeatRows=1, colWidths=[40 * mm, 32 * mm, 30 * mm, 25 * mm, 30 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    if rep["state_transitions"]:
        story.append(Paragraph("State Transitions", styles["Heading2"]))
        trows = [["Time", "Backend", "Change", "Reason"]]
        for t in rep["state_transitions"][:25]:
            trows.append([str(t.get("timestamp")), str(t.get("backend")),
                          f"{t.get('from_state')} -> {t.get('to_state')}",
                          str(t.get("reason"))])
        ttbl = Table(trows, repeatRows=1, colWidths=[35 * mm, 35 * mm, 40 * mm, 65 * mm])
        ttbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), accent),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
        ]))
        story.append(ttbl)
        story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Simulation only - backends are in-process mock objects and no packets were sent. "
        "Round-robin distributes evenly across equal-weight healthy backends; weighted WRR "
        "scales by weight; least-connections balances active load; ip-hash provides session "
        "affinity per client IP.", styles["Normal"]))
    doc.build(story)
    return path


def export(sim, fmt: str, path: str) -> str:
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_txt(sim))
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(sim))
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(sim))
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(sim))
    elif fmt == "pdf":
        to_pdf(sim, path)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return path
