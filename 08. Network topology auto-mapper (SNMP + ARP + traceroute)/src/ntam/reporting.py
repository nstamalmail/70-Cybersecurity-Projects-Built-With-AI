"""Report export engine for NTAM: JSON/CSV/HTML/PDF/TXT + Graphviz DOT."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


TYPE_COLORS = {"router": "#e74c3c", "switch": "#3498db", "server": "#2ecc71",
               "host": "#95a5a6", "unknown": "#f39c12"}


def build_report(topo) -> dict:
    devices = topo.devices if isinstance(topo.devices, list) else []
    by_type: dict = {}
    vendors: dict = {}
    snmp_ok = 0
    for d in devices:
        if isinstance(d, dict):
            dtype = d.get("device_type", "unknown")
            vendor = d.get("vendor") or "unknown"
            snmp_ok += 1 if d.get("snmp_accessible") else 0
            ip, mac, hostname = d.get("ip"), d.get("mac"), d.get("hostname")
        else:
            dtype = d.device_type
            vendor = d.vendor or "unknown"
            snmp_ok += 1 if d.snmp_accessible else 0
            ip, mac, hostname = d.ip, d.mac, d.hostname
        by_type[dtype] = by_type.get(dtype, 0) + 1
        vendors[vendor] = vendors.get(vendor, 0) + 1
    links = topo.links if isinstance(topo.links, list) else []
    return {
        "title": "Network Topology Report",
        "topology_id": topo.topology_id,
        "timestamp": topo.timestamp.isoformat(timespec="seconds") if isinstance(topo.timestamp, datetime) else str(topo.timestamp),
        "seed_ip": topo.seed_ip,
        "subnets": list(topo.subnets),
        "discovery_duration": topo.discovery_duration,
        "device_count": len(devices),
        "link_count": len(links),
        "by_type": by_type,
        "vendors": dict(sorted(vendors.items(), key=lambda kv: -kv[1])),
        "snmp_accessible": snmp_ok,
        "devices": devices,
        "links": links,
        "traceroute": getattr(topo, "traceroute", None),
    }


def to_dot(topo) -> str:
    """Graphviz DOT of the topology."""
    rep = build_report(topo)
    id_map = {}
    lines = ["graph topology {", "  layout=neato; overlap=false;",
             "  node [shape=box style=filled fontname='Segoe UI' fontsize=10];"]
    for i, d in enumerate(rep["devices"]):
        if isinstance(d, dict):
            did, ip, dtype = d.get("device_id"), d.get("ip"), d.get("device_type", "unknown")
            label = f"{d.get('hostname') or ip}\\n{ip}"
        else:
            did, ip, dtype = d.device_id, d.ip, d.device_type
            label = f"{d.hostname or d.ip}\\n{d.ip}"
        id_map[did] = i
        color = TYPE_COLORS.get(dtype, "#95a5a6")
        font = "white" if dtype in ("router", "switch") else "black"
        lines.append(f'  n{i} [label="{label}" fillcolor="{color}" fontcolor="{font}"];')
    for l in rep["links"]:
        if isinstance(l, dict):
            src, dst, ltype = l.get("source_device"), l.get("dest_device"), l.get("link_type", "")
        else:
            src, dst, ltype = l.source_device, l.dest_device, l.link_type
        if src in id_map and dst in id_map:
            lines.append(f'  n{id_map[src]} -- n{id_map[dst]} [label="{ltype}"];')
    lines.append("}")
    return "\n".join(lines)


def to_json(topo) -> str:
    payload = build_report(topo)
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2, default=str)


def to_csv(topo) -> str:
    rep = build_report(topo)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "mac", "hostname", "vendor", "device_type", "snmp_accessible"])
    for d in rep["devices"]:
        if isinstance(d, dict):
            writer.writerow([d.get("ip"), d.get("mac"), d.get("hostname"), d.get("vendor"),
                             d.get("device_type"), d.get("snmp_accessible")])
        else:
            writer.writerow([d.ip, d.mac, d.hostname, d.vendor, d.device_type, d.snmp_accessible])
    return buf.getvalue()


def to_txt(topo) -> str:
    rep = build_report(topo)
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Topology ID : {rep['topology_id']}",
        f"Discovered  : {rep['timestamp']}",
        f"Seed        : {rep['seed_ip']}",
        f"Subnets     : {', '.join(rep['subnets'])}",
        f"Duration    : {rep['discovery_duration']:.1f}s",
        f"Devices     : {rep['device_count']} ({rep['snmp_accessible']} SNMP-accessible)",
        f"Links       : {rep['link_count']}",
        f"By type     : {rep['by_type']}",
        "",
        "[DEVICES]",
        f"{'IP':<16}{'MAC':<20}{'TYPE':<9}{'VENDOR':<16}HOSTNAME",
        "-" * 78,
    ]
    for d in rep["devices"]:
        if isinstance(d, dict):
            lines.append(f"{str(d.get('ip')):<16}{str(d.get('mac') or '-'):<20}"
                         f"{d.get('device_type', '?'):<9}{str(d.get('vendor') or '-'):<16}"
                         f"{d.get('hostname') or '-'}")
        else:
            lines.append(f"{d.ip:<16}{str(d.mac or '-'):<20}{d.device_type:<9}"
                         f"{str(d.vendor or '-'):<16}{d.hostname or '-'}")
    if rep.get("traceroute"):
        lines += ["", "[TRACEROUTE]"]
        for h in rep["traceroute"]:
            lines.append(f"  hop {h.get('hop')}: {h.get('ip') or '*'} "
                         f"{str(h.get('latency_ms') or '')} ms")
    lines += [
        "",
        "[METHOD]",
        "Discovery: ICMP ping sweep + system ARP correlation; SNMP (if enabled) is",
        "read-only GET of sysDescr/sysName. Traceroute shows the forward path only;",
        "asymmetric routing is not captured. Discovery requires network authorization.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(topo) -> str:
    rep = build_report(topo)
    type_rows = "".join(f"<span class='pill' style='background:{TYPE_COLORS.get(t, '#999')}'>"
                        f"{t}: {n}</span><br>" for t, n in rep["by_type"].items())
    dev_rows = ""
    for d in rep["devices"]:
        if isinstance(d, dict):
            ip, dtype = d.get("ip"), d.get("device_type", "unknown")
            color = TYPE_COLORS.get(dtype, "#999")
            dev_rows += (f"<tr><td><b>{_esc(ip)}</b></td><td>{_esc(d.get('mac') or '-')}</td>"
                         f"<td><span class='badge' style='background:{color}'>{_esc(dtype)}</span></td>"
                         f"<td>{_esc(d.get('vendor') or '-')}</td><td>{_esc(d.get('hostname') or '-')}</td>"
                         f"<td>{'yes' if d.get('snmp_accessible') else 'no'}</td></tr>")
        else:
            color = TYPE_COLORS.get(d.device_type, "#999")
            dev_rows += (f"<tr><td><b>{_esc(d.ip)}</b></td><td>{_esc(d.mac or '-')}</td>"
                         f"<td><span class='badge' style='background:{color}'>{_esc(d.device_type)}</span></td>"
                         f"<td>{_esc(d.vendor or '-')}</td><td>{_esc(d.hostname or '-')}</td>"
                         f"<td>{'yes' if d.snmp_accessible else 'no'}</td></tr>")
    trace_rows = ""
    if rep.get("traceroute"):
        trace_rows = "".join(
            f"<tr><td>{h.get('hop')}</td><td>{_esc(h.get('ip') or '*')}</td>"
            f"<td>{h.get('latency_ms') or '-'} ms</td></tr>"
            for h in rep["traceroute"])
        trace_html = (f"<h2>Traceroute</h2><table><tr><th>Hop</th><th>IP</th><th>Latency</th></tr>"
                      f"{trace_rows}</table>")
    else:
        trace_html = ""
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
.badge {{ color: #fff; padding: 2px 10px; border-radius: 10px; font-size: 12px; font-weight: bold; }}
.meta {{ color: #5a6272; font-size: 13px; }}
.cards {{ display: flex; gap: 14px; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #d8dde8; border-radius: 8px; padding: 14px 20px;
         flex: 1; text-align: center; }}
.card .num {{ font-size: 24px; font-weight: bold; color: {theme.ACCENT_DIM}; }}
.pill {{ color:#fff; border-radius:10px; padding:1px 8px; font-size:12px; display:inline-block; }}
.note {{ background: #fff8e1; border-left: 4px solid {theme.YELLOW}; padding: 10px 14px; }}
</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">Topology {rep['topology_id']} &middot; discovered {rep['timestamp']} &middot;
seed {rep['seed_ip']} &middot; subnets {_esc(', '.join(rep['subnets']))} &middot;
{rep['discovery_duration']:.1f}s</p>
<div class="cards">
<div class="card"><div class="num">{rep['device_count']}</div>devices</div>
<div class="card"><div class="num">{rep['link_count']}</div>links</div>
<div class="card"><div class="num">{rep['snmp_accessible']}</div>SNMP-accessible</div>
</div>
<p><b>Device types:</b><br>{type_rows or '-'}</p>
<h2>Device Inventory</h2>
<table><tr><th>IP</th><th>MAC</th><th>Type</th><th>Vendor</th><th>Hostname</th><th>SNMP</th></tr>
{dev_rows}</table>
{trace_html}
<div class="note">Discovery used ICMP ping sweep + ARP correlation (SNMP read-only where
enabled). Traceroute captures the forward path only. Only run discovery on networks you
are authorized to scan.</div>
<p class="meta">Generated by NTAM &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
</body></html>"""


def to_pdf(topo, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    rep = build_report(topo)
    accent = colors.HexColor(theme.ACCENT_DIM)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm)
    type_str = ", ".join(f"{t}: {n}" for t, n in rep["by_type"].items()) or "-"
    story = [
        Paragraph(rep["title"], styles["Title"]),
        Paragraph(f"Topology {rep['topology_id']} - {rep['timestamp']} - seed {rep['seed_ip']} "
                  f"- {rep['device_count']} devices / {rep['link_count']} links in "
                  f"{rep['discovery_duration']:.1f}s", styles["Normal"]),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>Types:</b> {type_str} - <b>SNMP-accessible:</b> {rep['snmp_accessible']} "
                  f"- <b>Subnets:</b> {', '.join(rep['subnets'])}", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Device Inventory", styles["Heading2"]),
    ]
    rows = [["IP", "MAC", "Type", "Vendor", "Hostname"]]
    for d in rep["devices"][:40]:
        if isinstance(d, dict):
            rows.append([str(d.get("ip")), str(d.get("mac") or "-"),
                         str(d.get("device_type")), str(d.get("vendor") or "-"),
                         str(d.get("hostname") or "-")])
        else:
            rows.append([str(d.ip), str(d.mac or "-"), str(d.device_type),
                         str(d.vendor or "-"), str(d.hostname or "-")])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "-", "no devices found"])
    tbl = Table(rows, repeatRows=1, colWidths=[32 * mm, 45 * mm, 25 * mm, 35 * mm, 38 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Methodology & Authorization Note", styles["Heading2"]))
    story.append(Paragraph(
        "Discovery used an ICMP ping sweep with ARP-cache correlation; SNMP queries "
        "(read-only GET of sysDescr/sysName) enriched devices where community strings "
        "were provided. Traceroute reveals only the forward path; asymmetric routing is "
        "not captured. Network discovery generates traffic - run only on networks you are "
        "authorized to scan.", styles["Normal"]))
    doc.build(story)
    return path


def export(topo, fmt: str, path: str) -> str:
    fmt = fmt.lower()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_txt(topo))
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(topo))
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(topo))
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_html(topo))
    elif fmt == "pdf":
        to_pdf(topo, path)
    elif fmt == "dot":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_dot(topo))
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return path
