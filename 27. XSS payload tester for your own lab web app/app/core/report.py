"""Report exporters for XPT: HTML, CSV, JSON (stdlib only)."""

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
<title>XPT Report - {title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  .sev-critical {{ background: #b71c1c; color: #fff; font-weight: bold; }}
  .sev-high {{ background: #e53935; color: #fff; }}
  .sev-medium {{ background: #fb8c00; }}
  .sev-low {{ background: #fdd835; }}
  .sev-info {{ background: #bdbdbd; }}
  .conf {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
           background: #eee; margin-left: 6px; }}
  .confirmed {{ background: #2e7d32; color: #fff; }}
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 8px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow: auto; }}
  .meta {{ color: #555; font-size: 13px; }}
</style>
</head>
<body>
<h1>XPT — XSS Payload Tester Report</h1>
<p class="meta">
  Target: <b>{target}</b><br>
  Scan: {scan_id} &middot; Started: {started} &middot; Finished: {finished}<br>
  Parameters tested: {params} &middot; Payloads: {payloads} &middot;
  Requests: {requests} &middot; Findings: {findings} &middot; Errors: {errors}<br>
  CSP on target: {csp}
</p>
{body}
</body>
</html>
"""


def _sort(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9))


def _finding_card(f: Dict[str, Any]) -> str:
    sev = html.escape(f.get("severity", "info"))
    confirmed = "browser-confirmed" if f.get("browser_confirmed") else "reflection"
    conf_cls = "confirmed" if f.get("browser_confirmed") else "conf"
    return f"""
<div class="finding">
<h2><span class="sev-{sev}">{sev.upper()}</span>
 {html.escape(f.get('xss_type', ''))} XSS @
 {html.escape(f.get('parameter_location', ''))}:{html.escape(f.get('parameter_name', ''))}
 <span class="{conf_cls}">{confirmed}</span></h2>
<p><b>URL:</b> {html.escape(f.get('url', ''))}<br>
<b>Context:</b> {html.escape(f.get('context', ''))} &middot;
<b>Encoding:</b> {html.escape(f.get('encoding_applied') or 'none')} &middot;
<b>Confirmation:</b> {html.escape(f.get('confirmation_method', ''))}<br>
<b>Signal:</b> {html.escape(str(f.get('signal', '')))}<br>
<b>Payload:</b> <code>{html.escape(f.get('payload', ''))}</code></p>
<h3>Reflection snippet</h3><pre>{html.escape(f.get('reflection_snippet', ''))}</pre>
<h3>Request</h3><pre>{html.escape(f.get('request', ''))}</pre>
<h3>Response</h3><pre>{html.escape(f.get('response_snippet', ''))}</pre>
<h3>Remediation</h3><pre>{html.escape(f.get('remediation', ''))}</pre>
</div>"""


def export_html(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]],
                started: str = "n/a", finished: str = "n/a") -> str:
    findings = _sort(findings)
    body = f"<h2>Findings ({len(findings)})</h2>"
    if findings:
        body += "".join(_finding_card(f) for f in findings)
    else:
        body += "<p>No XSS findings.</p>"
    doc = _TEMPLATE.format(
        title=html.escape(scan.get("target", "scan")),
        target=html.escape(scan.get("target", "")),
        scan_id=html.escape(str(scan.get("id", ""))),
        started=html.escape(started), finished=html.escape(finished),
        params=scan.get("parameters_tested", 0),
        payloads=scan.get("payloads_used", 0),
        requests=scan.get("total_requests", 0),
        errors=scan.get("errors", 0),
        findings=scan.get("findings_count", len(findings)),
        csp="yes" if scan.get("csp_present") else "no / not recorded",
        body=body,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


CSV_FIELDS = ["severity", "confidence", "xss_type", "context", "parameter_location",
              "parameter_name", "encoding_applied", "browser_confirmed",
              "confirmation_method", "signal", "payload", "url", "method", "status"]


def export_csv(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    findings = _sort(findings)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for f in findings:
            writer.writerow([f.get(k, "") for k in CSV_FIELDS])
    return path


def export_json(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]],
                started: str = "n/a", finished: str = "n/a") -> str:
    doc = {
        "tool": "XPT", "version": 1,
        "scan": {**scan, "started_at": started, "finished_at": finished},
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_all(scan: Dict[str, Any], findings: List[Dict[str, Any]], directory: str,
               started: str = "n/a", finished: str = "n/a") -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    base = os.path.join(directory, f"xpt_scan_{scan.get('id', 'x')}")
    return {
        "html": export_html(base + ".html", scan, findings, started, finished),
        "csv": export_csv(base + ".csv", scan, findings),
        "json": export_json(base + ".json", scan, findings, started, finished),
    }
