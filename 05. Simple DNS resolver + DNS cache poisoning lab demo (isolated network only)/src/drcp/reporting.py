"""Report export engine for DRCP: TXT/JSON/CSV/HTML/PDF lab reports."""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

import theme


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _entry_field(entries, field_name):
    """Entries may be CacheEntry objects (live run) or dicts (imported)."""
    if not entries:
        return []
    first = entries[0]
    if hasattr(first, field_name):
        return [getattr(e, field_name) for e in entries]
    return [e.get(field_name) for e in entries]


def build_report(s) -> dict:
    if s.cache_after and hasattr(s.cache_after[0], "source"):
        poisoned = [e for e in s.cache_after if e.source == "forged"]
        cache_dump = [{"domain": e.domain, "type": e.record_type, "value": e.value,
                       "ttl": e.expires_in(), "source": e.source} for e in s.cache_after]
    else:
        poisoned = [e for e in s.cache_after if e.get("source") == "forged"]
        cache_dump = list(s.cache_after)
    if s.cache_before and hasattr(s.cache_before[0], "source"):
        before_dump = [{"domain": e.domain, "type": e.record_type, "value": e.value,
                        "ttl": e.expires_in(), "source": e.source} for e in s.cache_before]
    else:
        before_dump = list(s.cache_before)
    return {
        "title": "DNS Cache Poisoning Lab Report",
        "lab_id": s.lab_id,
        "timestamp": s.timestamp.isoformat(timespec="seconds"),
        "resolver_port": s.resolver_port,
        "upstream_port": s.upstream_port,
        "target_domain": s.target_domain,
        "legitimate_answer": s.legitimate_answer,
        "forged_answer": s.forged_answer,
        "port_randomization": s.port_randomization,
        "dnssec_mode": s.dnssec_mode,
        "strategy": s.strategy,
        "attempts": s.attempts,
        "poisoning_successful": s.poisoning_successful,
        "cache_before": before_dump,
        "cache_after": cache_dump,
        "poisoned_entries": len(poisoned),
        "steps": list(s.steps),
        "resolver_log": list(s.resolver_log),
        "attack_log": list(s.attack_log),
    }


def to_json(s) -> str:
    payload = build_report(s)
    payload["report_generated"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2, default=str)


def to_csv(s) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    rep = build_report(s)
    writer.writerow(["cache_after: domain", "type", "value", "ttl", "source"])
    for e in rep["cache_after"]:
        writer.writerow([e.get("domain"), e.get("type"), e.get("value"),
                         e.get("ttl"), e.get("source")])
    writer.writerow([])
    writer.writerow(["resolver_log: time", "kind", "detail"])
    for ev in rep["resolver_log"]:
        writer.writerow([ev.get("ts"), ev.get("kind"), ev.get("detail")])
    writer.writerow([])
    writer.writerow(["attack_log: time", "message"])
    for ev in rep["attack_log"]:
        writer.writerow([ev.get("ts"), ev.get("msg")])
    return buf.getvalue()


def to_txt(s) -> str:
    rep = build_report(s)
    lines = [
        "=" * 70,
        f"  {rep['title']}",
        "=" * 70,
        f"Lab ID          : {rep['lab_id']}",
        f"Date            : {rep['timestamp']}",
        f"Resolver port   : {rep['resolver_port']}   Upstream port: {rep['upstream_port']}",
        f"Target domain   : {rep['target_domain']}",
        f"Legit answer    : {rep['legitimate_answer']}",
        f"Forged answer   : {rep['forged_answer']}",
        f"Port randomization: {'ON' if rep['port_randomization'] else 'OFF'}",
        f"DNSSEC mode     : {'ON' if rep['dnssec_mode'] else 'OFF'}",
        f"Guess strategy  : {rep['strategy']}",
        f"Attempts        : {rep['attempts']}",
        f"Poisoning result: {'SUCCESSFUL (cache poisoned)' if rep['poisoning_successful'] else 'FAILED (defenses held)'}",
        "",
        "[CACHE BEFORE]",
    ]
    for e in rep["cache_before"]:
        lines.append(f"  {e.get('domain'):<24} {e.get('value'):<16} TTL {e.get('ttl')} ({e.get('source')})")
    if not rep["cache_before"]:
        lines.append("  (empty)")
    lines.append("[CACHE AFTER]")
    for e in rep["cache_after"]:
        flag = "  <-- POISONED" if e.get("source") == "forged" else ""
        lines.append(f"  {e.get('domain'):<24} {e.get('value'):<16} TTL {e.get('ttl')} ({e.get('source')}){flag}")
    if not rep["cache_after"]:
        lines.append("  (empty)")
    lines += ["", "[RESOLVER LOG]"]
    for ev in rep["resolver_log"]:
        lines.append(f"  {ev.get('ts')} {ev.get('kind'):<10} {ev.get('detail')}")
    lines += ["", "[ATTACK LOG]"]
    for ev in rep["attack_log"]:
        lines.append(f"  {ev.get('ts')} {ev.get('msg')}")
    lines += [
        "",
        "[DEFENSE RECOMMENDATIONS]",
        "- Deploy DNSSEC validation: forged responses lack valid RRSIG signatures and are rejected.",
        "- Randomize UDP source ports: raises attacker search space beyond 1 billion attempts.",
        "- The demo attack succeeded only with 'known' strategy (educational omniscience);",
        "  real attacks must guess the 16-bit txn ID - about 65,536 tries on average.",
        "",
        "ISOLATED LAB ONLY - never aim this tool at production DNS infrastructure.",
        "=" * 70,
    ]
    return "\n".join(lines)


def to_html(s) -> str:
    rep = build_report(s)
    verdict = ("style='background:#e74c3c;color:#fff;padding:6px 14px;border-radius:6px;font-weight:bold'"
               if rep["poisoning_successful"] else
               "style='background:#2ecc71;color:#fff;padding:6px 14px;border-radius:6px;font-weight:bold'")
    verdict_text = "POISONING SUCCESSFUL" if rep["poisoning_successful"] else "DEFENSES HELD"
    rows_before = "".join(
        f"<tr><td>{_esc(e.get('domain'))}</td><td>{_esc(e.get('value'))}</td>"
        f"<td>{e.get('ttl')}</td><td>{e.get('source')}</td></tr>"
        for e in rep["cache_before"]) or "<tr><td colspan='4'>(empty)</td></tr>"
    rows_after = "".join(
        f"<tr><td>{_esc(e.get('domain'))}</td><td>{_esc(e.get('value'))}</td>"
        f"<td>{e.get('ttl')}</td><td>{e.get('source')}"
        + (" <b style='color:#e74c3c'>POISONED</b>" if e.get("source") == "forged" else "")
        + "</td></tr>"
        for e in rep["cache_after"]) or "<tr><td colspan='4'>(empty)</td></tr>"
    res_rows = "".join(
        f"<tr><td>{_esc(ev.get('ts'))}</td><td>{_esc(ev.get('kind'))}</td>"
        f"<td>{_esc(ev.get('detail'))}</td></tr>"
        for ev in rep["resolver_log"]) or "<tr><td colspan='3'>-</td></tr>"
    atk_rows = "".join(
        f"<tr><td>{_esc(ev.get('ts'))}</td><td>{_esc(ev.get('msg'))}</td></tr>"
        for ev in rep["attack_log"]) or "<tr><td colspan='2'>-</td></tr>"
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
.note {{ background: #fdecea; border-left: 4px solid {theme.RED}; padding: 10px 14px; border-radius: 4px; }}
</style></head><body>
<h1>{rep['title']}</h1>
<p class="meta">Lab {rep['lab_id']} &middot; {rep['timestamp']} &middot; resolver :{rep['resolver_port']} &middot;
upstream :{rep['upstream_port']}</p>
<p><span {verdict}>{verdict_text}</span> &nbsp; strategy <b>{rep['strategy']}</b> &middot;
{rep['attempts']} attempts &middot; port randomization {'ON' if rep['port_randomization'] else 'OFF'}
&middot; DNSSEC {'ON' if rep['dnssec_mode'] else 'OFF'}</p>
<div class="note">Educational demonstration on an isolated lab network. The forged answer
<b>{_esc(rep['forged_answer'])}</b> {'WAS' if rep['poisoning_successful'] else 'WAS NOT'} accepted
for <b>{_esc(rep['target_domain'])}</b> (legitimate: {_esc(rep['legitimate_answer'])}).</div>
<h2>Cache Before</h2>
<table><tr><th>Domain</th><th>Value</th><th>TTL</th><th>Source</th></tr>{rows_before}</table>
<h2>Cache After</h2>
<table><tr><th>Domain</th><th>Value</th><th>TTL</th><th>Source</th></tr>{rows_after}</table>
<h2>Resolver Log</h2>
<table><tr><th>Time</th><th>Kind</th><th>Detail</th></tr>{res_rows}</table>
<h2>Attack Log</h2>
<table><tr><th>Time</th><th>Message</th></tr>{atk_rows}</table>
<h2>Defensive Recommendations</h2>
<ul>
<li><b>DNSSEC validation</b> - the definitive mitigation: forged responses lack valid RRSIG signatures.</li>
<li><b>Source port randomization</b> - pushes the attacker's search space past a billion attempts.</li>
<li>Query enforcement (bailiwick checking) and response hardening on upstream links.</li>
</ul>
<p class="meta">Generated by DRCP &mdash; {datetime.now().isoformat(timespec='seconds')}</p>
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
        Paragraph(f"Lab {rep['lab_id']} - {rep['timestamp']} - resolver :{rep['resolver_port']} "
                  f"- upstream :{rep['upstream_port']}", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Result:</b> {'POISONING SUCCESSFUL' if rep['poisoning_successful'] else 'DEFENSES HELD'} "
            f"({rep['attempts']} attempts, strategy {rep['strategy']}, "
            f"port randomization {'ON' if rep['port_randomization'] else 'OFF'}, "
            f"DNSSEC {'ON' if rep['dnssec_mode'] else 'OFF'})<br/>"
            f"Target {rep['target_domain']}: legitimate {rep['legitimate_answer']} vs "
            f"forged {rep['forged_answer']}",
            styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Cache After Attack", styles["Heading2"]),
    ]
    rows = [["Domain", "Value", "TTL", "Source"]]
    for e in rep["cache_after"]:
        rows.append([str(e.get("domain")), str(e.get("value")), str(e.get("ttl")),
                     str(e.get("source")) + (" POISONED" if e.get("source") == "forged" else "")])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "cache empty"])
    tbl = Table(rows, repeatRows=1, colWidths=[55 * mm, 45 * mm, 25 * mm, 50 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Resolver Log (key events)", styles["Heading2"]))
    ev_rows = [["Time", "Kind", "Detail"]]
    for ev in rep["resolver_log"][:25]:
        ev_rows.append([str(ev.get("ts")), str(ev.get("kind")), str(ev.get("detail"))[:90]])
    if len(ev_rows) == 1:
        ev_rows.append(["-", "-", "no events recorded"])
    etbl = Table(ev_rows, repeatRows=1, colWidths=[30 * mm, 30 * mm, 115 * mm])
    etbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9cfdd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef1f7")]),
    ]))
    story.append(etbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Defensive Recommendations", styles["Heading2"]))
    story.append(Paragraph(
        "DNSSEC validation is the definitive mitigation - forged responses lack valid RRSIG "
        "signatures and are rejected. Source port randomization raises the attacker's search "
        "space past a billion attempts. Deploy bailiwick checking on recursive resolvers. "
        "This lab ran on an isolated network only - never aim the tool at production DNS.",
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
