"""Report exporters for SIDT: HTML, CSV, JSON (Jinja-free, stdlib only)."""

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
<title>SIDT Report - {title}</title>
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
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 8px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow: auto; }}
  .meta {{ color: #555; font-size: 13px; }}
</style>
</head>
<body>
<h1>SIDT — SQL Injection Detection Report</h1>
<p class="meta">
  Target: <b>{target}</b><br>
  Scan: {scan_id} &middot; Started: {started} &middot; Finished: {finished}<br>
  Parameters tested: {params} &middot; Requests: {requests} &middot;
  Findings: {findings} &middot; Errors: {errors}<br>
  Safe mode: {safe_mode} &middot; WAF detected: {waf}
</p>
{body}
</body>
</html>
"""


def _sort(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9))


def _finding_card(f: Dict[str, Any]) -> str:
    sev = html.escape(f.get("severity", "info"))
    delta = f.get("response_delta") or {}
    return f"""
<div class="finding">
<h2><span class="sev-{sev}">{sev.upper()}</span>
 {html.escape(f.get('parameter_location', ''))}:{html.escape(f.get('parameter_name', ''))}
 — {html.escape(f.get('technique', ''))}-based ({html.escape(f.get('confidence', ''))} confidence)</h2>
<p><b>URL:</b> {html.escape(f.get('url', ''))}<br>
<b>Method:</b> {html.escape(f.get('method', ''))}<br>
<b>DBMS hint:</b> {html.escape(f.get('dbms_hint') or 'n/a')}<br>
<b>Signal:</b> {html.escape(str(f.get('signal', '')))}<br>
<b>Payload:</b> <code>{html.escape(f.get('payload', ''))}</code><br>
<b>Response delta:</b> {html.escape(json.dumps(delta, default=str))}</p>
<h3>Baseline request</h3><pre>{html.escape(f.get('baseline_request', ''))}</pre>
<h3>Injected request</h3><pre>{html.escape(f.get('injected_request', ''))}</pre>
<h3>Baseline response</h3><pre>{html.escape(f.get('baseline_response_snippet', ''))}</pre>
<h3>Injected response</h3><pre>{html.escape(f.get('injected_response_snippet', ''))}</pre>
<h3>Remediation</h3><pre>{html.escape(f.get('remediation', ''))}</pre>
</div>"""


def export_html(path: str, scan: Dict[str, Any], findings: List[Dict[str, Any]],
                started: str = "n/a", finished: str = "n/a") -> str:
    findings = _sort(findings)
    body = "<h2>Findings ({n})</h2>".format(n=len(findings))
    if findings:
        body += "".join(_finding_card(f) for f in findings)
    else:
        body += "<p>No SQL injection findings. Continue hardening; see coverage below.</p>"
    body += f"<h2>Coverage</h2><p>Parameters tested: {scan.get('parameters_tested', 0)}; " \
            f"techniques used: {html.escape(', '.join(scan.get('techniques_used', []) or ['n/a']))}</p>"
    doc = _TEMPLATE.format(
        title=html.escape(scan.get("target", "scan")),
        target=html.escape(scan.get("target", "")),
        scan_id=html.escape(str(scan.get("id", ""))),
        started=html.escape(started), finished=html.escape(finished),
        params=scan.get("parameters_tested", 0),
        requests=scan.get("total_requests", 0),
        errors=scan.get("errors", 0),
        findings=scan.get("findings_count", len(findings)),
        safe_mode=str(scan.get("safe_mode", "")),
        waf=html.escape(scan.get("waf", "") or "none"),
        body=body,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


CSV_FIELDS = ["severity", "confidence", "technique", "parameter_location",
              "parameter_name", "dbms_hint", "signal", "payload", "url",
              "method", "status", "resp_time_ms"]


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
        "tool": "SIDT", "version": 1,
        "scan": {**scan, "started_at": started, "finished_at": finished},
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_all(scan: Dict[str, Any], findings: List[Dict[str, Any]], directory: str,
               started: str = "n/a", finished: str = "n/a") -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    base = os.path.join(directory, f"sidt_scan_{scan.get('id', 'x')}")
    return {
        "html": export_html(base + ".html", scan, findings, started, finished),
        "csv": export_csv(base + ".csv", scan, findings),
        "json": export_json(base + ".json", scan, findings, started, finished),
    }
