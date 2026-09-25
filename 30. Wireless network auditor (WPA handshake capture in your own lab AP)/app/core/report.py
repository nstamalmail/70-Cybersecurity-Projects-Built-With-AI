"""Audit report exporters for WNA: HTML, CSV, JSON (stdlib only)."""

from __future__ import annotations

import csv
import html
import json
import os
from typing import Any, Dict, List

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WNA Audit Report - {title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  .ok {{ background: #2e7d32; color: #fff; padding: 2px 10px; border-radius: 4px; }}
  .partial {{ background: #fb8c00; color: #fff; padding: 2px 10px; border-radius: 4px; }}
  .none {{ background: #bdbdbd; color: #fff; padding: 2px 10px; border-radius: 4px; }}
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 8px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow: auto; }}
  .meta {{ color: #555; font-size: 13px; }}
</style>
</head>
<body>
<h1>WNA — Wireless Network Audit Report</h1>
<p class="meta">
  Audit: {title} &middot; Generated: {generated}<br>
  Scope (allowlist BSSIDs): {allowlist}<br>
  Adapter: {adapter} &middot; Capture method: {method}<br>
  Targets assessed: {targets}
</p>
<h2>Posture summary</h2>
<p>This report validates the security posture of lab access points within the
declared scope. Evidence: capture files, EAPOL message completeness, hash
material, and (where attempted) PSK resilience. Hardening recommendations are
listed per target.</p>
{body}
</body>
</html>
"""


def _badge(completeness: str) -> str:
    cls = {"complete": "ok", "partial": "partial"}.get(completeness, "none")
    return f"<span class='{cls}'>{html.escape(completeness.upper())}</span>"


def _target_card(t: Dict[str, Any]) -> str:
    return f"""
<h3>{html.escape(t.get('essid') or t.get('bssid', 'target'))}
 <span class="badge">{html.escape(t.get('encryption', ''))}</span></h3>
<table>
<tr><th>BSSID</th><th>Channel</th><th>Handshake</th><th>PMKID</th>
    <th>Crack attempted</th><th>Result</th></tr>
<tr><td>{html.escape(t.get('bssid', ''))}</td>
    <td>{t.get('channel', '')}</td>
    <td>{_badge(t.get('handshake_completeness', 'none'))}
        ({html.escape(', '.join(t.get('messages_present', []) or []))})</td>
    <td>{'yes' if t.get('pmkid_captured') else 'no'}</td>
    <td>{html.escape(t.get('crack_tool') or 'no')}</td>
    <td>{'PSK cracked: <b>' + html.escape(t.get('crack_result')) + '</b>'
         if t.get('crack_result') else 'not cracked / not attempted'}</td></tr>
</table>
<h4>Hardening recommendations</h4>
<pre>{html.escape(_recommendations(t))}</pre>
"""


def _recommendations(t: Dict[str, Any]) -> str:
    recs = []
    enc = (t.get("encryption") or "").upper()
    if t.get("crack_result"):
        recs.append("PSK was recovered from the wordlist — replace it with a "
                    "long random passphrase (16+ chars) or move to WPA3-SAE "
                    "/ enterprise auth.")
    if "WPA2" in enc and "Enterprise" not in enc:
        recs.append("WPA2-PSK is offline-crackable after one handshake: "
                    "prefer WPA3-SAE (or WPA2/WPA3 mixed with SAE required "
                    "for capable clients).")
    if t.get("handshake_completeness") == "complete":
        recs.append("A complete 4-way handshake is obtainable in your lab — "
                    "assume PSK-only networks are exposed to offline attacks "
                    "by anyone in radio range.")
    if not t.get("handshake_captured") and not t.get("pmkid_captured"):
        recs.append("No handshake material in scope — re-verify with a client "
                    "(re)connection; posture conclusion pending.")
    recs.append("General: disable WPS, use a unique SSID (not disclosing "
                "model/site), and rotate PSKs on staff turnover.")
    return "\n".join(f"- {r}" for r in recs)


def export_html(path: str, audit: Dict[str, Any],
                targets: List[Dict[str, Any]]) -> str:
    body = ""
    if targets:
        body = "".join(_target_card(t) for t in targets)
    else:
        body = "<p>No targets assessed.</p>"
    doc = _TEMPLATE.format(
        title=html.escape(audit.get("audit_id", "") or "audit"),
        generated=html.escape(audit.get("generated", "")),
        allowlist=html.escape(", ".join(audit.get("allowlist", []) or [])
                              or "(not recorded)"),
        adapter=html.escape(audit.get("adapter", "") or "n/a"),
        method=html.escape(audit.get("capture_method", "")),
        targets=len(targets),
        body=body,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


CSV_FIELDS = ["bssid", "essid", "channel", "encryption", "handshake_captured",
              "handshake_completeness", "messages_present", "pmkid_captured",
              "hash_file", "crack_attempted", "crack_tool", "crack_result",
              "crack_duration_seconds"]


def export_csv(path: str, audit: Dict[str, Any],
               targets: List[Dict[str, Any]]) -> str:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        for t in targets:
            row = dict(t)
            row["messages_present"] = ",".join(row.get("messages_present", []) or [])
            writer.writerow([row.get(k, "") for k in CSV_FIELDS])
    return path


def export_json(path: str, audit: Dict[str, Any],
                targets: List[Dict[str, Any]]) -> str:
    doc = {"tool": "WNA", "version": 1, "audit": audit, "targets": targets}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_all(audit: Dict[str, Any], targets: List[Dict[str, Any]],
               directory: str) -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    base = os.path.join(directory, f"wna_audit_{audit.get('id', 'x')}")
    return {
        "html": export_html(base + ".html", audit, targets),
        "csv": export_csv(base + ".csv", audit, targets),
        "json": export_json(base + ".json", audit, targets),
    }
