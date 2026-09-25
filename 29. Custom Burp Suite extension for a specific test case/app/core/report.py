"""Report exporters for CBSEF: HTML, CSV, JSON (stdlib only)."""

from __future__ import annotations

import csv
import html
import json
import os
from typing import Any, Dict, List

CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

TEST_CASE_NAMES = {
    "mass_assignment": "Mass assignment",
    "jwt_confusion": "JWT algorithm confusion",
    "oauth_redirect": "OAuth redirect_uri validation",
    "introspection": "GraphQL introspection",
}

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CBSEF Report - {title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  .meta {{ color: #555; font-size: 13px; }}
  .finding {{ border: 1px solid #ddd; border-radius: 6px; padding: 12px 16px; margin: 14px 0; }}
  .conf-candidate {{ background: #fff8e1; }}
  .conf-confirmed {{ background: #e8f5e9; }}
  .conf-false_positive {{ background: #fafafa; color: #888; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 11px;
            background: #eee; margin-right: 6px; }}
  .b-high {{ background: #e53935; color: #fff; }}
  .b-medium {{ background: #fb8c00; color: #fff; }}
  .b-low {{ background: #fdd835; }}
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 8px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow: auto; }}
</style>
</head>
<body>
<h1>CBSEF — Custom Test-Case Findings Report</h1>
<p class="meta">
  Session: {session} &middot; Generated: {generated}<br>
  Findings: {total} (confirmed: {confirmed}, candidates: {candidates},
  false positives: {fps})<br>
  Test case: {test_case}
</p>
{body}
</body>
</html>
"""


def _sort(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (
        0 if f.get("status") == "confirmed" else 1,
        CONF_ORDER.get(f.get("confidence", "low"), 3)))


def _finding_card(f: Dict[str, Any]) -> str:
    conf = html.escape(f.get("confidence", "low"))
    status = html.escape(f.get("status", "candidate"))
    delta = f.get("differential") or {}
    name = TEST_CASE_NAMES.get(f.get("test_case", ""),
                               f.get("test_case", ""))
    return f"""
<div class="finding conf-{status}">
<h2><span class="badge b-{conf}">{conf.upper()}</span>
 {html.escape(name)} — {html.escape(f.get('method', ''))} {html.escape(f.get('url', ''))}</h2>
<p><b>Status:</b> {status} &middot; <b>Parameter:</b> {html.escape(f.get('parameter') or 'n/a')}<br>
<b>Signal:</b> {html.escape(str(f.get('signal_description', '')))}<br>
<b>Differential:</b> {html.escape(json.dumps(delta, default=str))}</p>
<h3>Baseline request</h3><pre>{html.escape(f.get('baseline_request', ''))}</pre>
<h3>Baseline response</h3><pre>{html.escape(f.get('baseline_response', ''))}</pre>
<h3>Probe request</h3><pre>{html.escape(f.get('probe_request', ''))}</pre>
<h3>Probe response</h3><pre>{html.escape(f.get('probe_response', ''))}</pre>
<h3>Remediation</h3><pre>{html.escape(f.get('remediation', ''))}</pre>
</div>"""


def export_html(path: str, session: Dict[str, Any],
                findings: List[Dict[str, Any]]) -> str:
    findings = _sort(findings)
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    fps = sum(1 for f in findings if f.get("status") == "false_positive")
    body = f"<h2>Findings ({len(findings)})</h2>"
    body += "".join(_finding_card(f) for f in findings) if findings else \
        "<p>No findings in this session.</p>"
    doc = _TEMPLATE.format(
        title=html.escape(session.get("name", "session")),
        session=html.escape(str(session.get("id", ""))),
        generated=html.escape(session.get("generated", "")),
        total=len(findings), confirmed=confirmed,
        candidates=len(findings) - confirmed - fps, fps=fps,
        test_case=html.escape(session.get("test_case", "all")),
        body=body,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


CSV_FIELDS = ["finding_id", "test_case", "status", "confidence", "method",
              "url", "endpoint", "parameter", "signal_description"]


def export_csv(path: str, session: Dict[str, Any],
               findings: List[Dict[str, Any]]) -> str:
    findings = _sort(findings)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for f in findings:
            writer.writerow([f.get(k, "") for k in CSV_FIELDS])
    return path


def export_json(path: str, session: Dict[str, Any],
                findings: List[Dict[str, Any]]) -> str:
    doc = {"tool": "CBSEF", "version": 1, "session": session,
           "findings": findings}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_all(session: Dict[str, Any], findings: List[Dict[str, Any]],
               directory: str) -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    base = os.path.join(directory, f"cbsef_{session.get('id', 'x')}")
    return {
        "html": export_html(base + ".html", session, findings),
        "csv": export_csv(base + ".csv", session, findings),
        "json": export_json(base + ".json", session, findings),
    }
