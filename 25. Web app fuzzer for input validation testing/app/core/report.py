"""Report exporters: HTML, CSV, JSON."""

from __future__ import annotations

import csv
import html
import json
import os
from typing import Any, Dict, List

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebFuzzer Report - {title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%%; margin-top: 8px; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  .sev-critical {{ background: #b71c1c; color: #fff; font-weight: bold; }}
  .sev-high {{ background: #e53935; color: #fff; }}
  .sev-medium {{ background: #fb8c00; }}
  .sev-low {{ background: #fdd835; }}
  .sev-info {{ background: #bdbdbd; }}
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 8px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow: auto; }}
  .meta {{ color: #555; font-size: 13px; }}
  a {{ color: #1565c0; }}
</style>
</head>
<body>
<h1>WebFuzzer Security Report</h1>
<p class="meta">
  Target: <b>{target}</b><br>
  Started: {started} &middot; Finished: {finished}<br>
  Requests: {requests} &middot; Errors: {errors} &middot; Findings: {findings}<br>
  Scan ID: {scan_id}
</p>
{body}
</body>
</html>
"""


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9))


def export_html(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]],
                started: str = "n/a", finished: str = "n/a") -> str:
    findings = _sort_findings(findings)
    rows = []
    for f in findings:
        req = html.escape(f.get("request", ""))
        resp = html.escape(f.get("response", ""))
        sev = f.get("severity", "info")
        rows.append(f"""<tr>
<td><span class="sev-{sev}">{html.escape(sev.upper())}</span></td>
<td>{html.escape(f.get('category', ''))}</td>
<td>{html.escape(f.get('technique', ''))}</td>
<td>{html.escape(f.get('injection_kind', ''))}:{html.escape(f.get('injection_name', ''))}</td>
<td><a href="{html.escape(f.get('url', ''))}" target="_blank">{html.escape(f.get('url', ''))[:120]}</a></td>
<td>{f.get('status', '')}</td>
<td>{html.escape(f.get('payload', ''))}</td>
<td>{html.escape(f.get('encoding', ''))}</td>
<td>{html.escape(str(f.get('evidence', '')))}</td>
</tr>
<pre>{req}</pre><pre>{resp}</pre>""")
    table = ("<table><tr><th>Severity</th><th>Category</th><th>Technique</th>"
             "<th>Point</th><th>URL</th><th>Status</th><th>Payload</th>"
             "<th>Encoding</th><th>Evidence</th></tr>" + "\n".join(rows) + "</table>") if rows else "<p>No findings in this scan.</p>"
    body = "<h2>Findings</h2>" + table
    html_doc = _TEMPLATE.format(
        title=html.escape(scan.get("target", "scan")),
        target=html.escape(scan.get("target", "")),
        started=html.escape(started), finished=html.escape(finished),
        requests=scan.get("total_requests", 0), errors=scan.get("errors", 0),
        findings=scan.get("findings_count", len(findings)),
        scan_id=scan.get("id", ""),
        body=body,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return path


def export_csv(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    findings = _sort_findings(findings)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "category", "technique", "injection_kind",
                         "injection_name", "payload", "encoding", "url", "status",
                         "resp_len", "resp_time_ms", "evidence"])
        for f in findings:
            writer.writerow([f.get("severity"), f.get("category"), f.get("technique"),
                             f.get("injection_kind"), f.get("injection_name"),
                             f.get("payload"), f.get("encoding"), f.get("url"),
                             f.get("status"), f.get("resp_len"),
                             f.get("resp_time_ms"), f.get("evidence")])
    return path


def export_json(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]],
                started: str = "n/a", finished: str = "n/a") -> str:
    doc = {
        "tool": "WebFuzzer",
        "version": 1,
        "scan": {**scan, "started_at": started, "finished_at": finished},
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_all(scan: Dict[str, Any], findings: List[Dict[str, Any]], directory: str,
               started: str = "n/a", finished: str = "n/a") -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    base = os.path.join(directory, f"webfuzzer_scan_{scan.get('id', 'x')}")
    return {
        "html": export_html(base + ".html", scan, findings, started, finished),
        "csv": export_csv(base + ".csv", scan, findings),
        "json": export_json(base + ".json", scan, findings, started, finished),
    }