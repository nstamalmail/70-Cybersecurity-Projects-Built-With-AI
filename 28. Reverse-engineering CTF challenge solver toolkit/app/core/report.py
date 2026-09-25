"""Writeup exporters for RECT: Markdown, HTML, JSON (stdlib only)."""

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
<title>RECT Writeup - {title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  pre {{ background: #fafafa; border: 1px solid #eee; padding: 10px; font-size: 12.5px;
        white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow: auto; }}
  .meta {{ color: #555; font-size: 13px; }}
  .flag {{ background: #2e7d32; color: #fff; padding: 2px 10px; border-radius: 4px;
           font-family: Consolas, monospace; }}
  .op {{ border-left: 3px solid #1976d2; padding: 4px 10px; margin: 10px 0;
         background: #f5f8ff; }}
  .op .tool {{ color: #1976d2; font-weight: bold; }}
</style>
</head>
<body>
<h1>RECT Writeup — {title}</h1>
<p class="meta">
  Category: <b>{category}</b> &middot; Event: <b>{event}</b><br>
  Binary: <b>{binary}</b> &middot; Created: {created}<br>
  Status: {status}<br>
</p>
<h2>Description</h2>
<pre>{description}</pre>
<h2>Solution steps (replayable command log)</h2>
{ops}
<h2>Notes</h2>
<pre>{notes}</pre>
<h2>Flag</h2>
<p>{flag_html}</p>
</body>
</html>
"""


def _ops_html(records: List[Dict[str, Any]]) -> str:
    if not records:
        return "<p>(no recorded operations)</p>"
    out = []
    for r in records:
        mark = "✔" if r.get("success") else "✖"
        out.append(
            f"<div class='op'><span class='tool'>{html.escape(r.get('tool', ''))}"
            f"/{html.escape(r.get('operation', ''))}</span> {mark}<br>"
            f"<b>in:</b> {html.escape(str(r.get('input_summary', '')))[:160]}<br>"
            f"<b>out:</b> {html.escape(str(r.get('output_summary', '')))[:200]}"
            f"<pre>{html.escape(str(r.get('full_output', '')))[:4000]}</pre></div>")
    return "\n".join(out)


def _ops_md(records: List[Dict[str, Any]]) -> str:
    if not records:
        return "(no recorded operations)"
    out = []
    for r in records:
        mark = "✔" if r.get("success") else "✖"
        out.append(f"### {mark} {r.get('tool')}/{r.get('operation')}\n")
        out.append(f"- in: `{str(r.get('input_summary', ''))[:160]}`")
        out.append(f"- out: `{str(r.get('output_summary', ''))[:200]}`\n")
        out.append("```\n" + str(r.get("full_output", ""))[:4000] + "\n```\n")
    return "\n".join(out)


def export_markdown(path: str, challenge: Dict[str, Any],
                    records: List[Dict[str, Any]]) -> str:
    status = "SOLVED" if challenge.get("solved") else "in progress"
    flag = challenge.get("flag", "")
    doc = (
        f"# RECT Writeup — {challenge.get('name', 'challenge')}\n\n"
        f"- Category: {challenge.get('category', '')}\n"
        f"- Event: {challenge.get('event', '')}\n"
        f"- Binary: `{challenge.get('binary_path', '')}`\n"
        f"- Status: **{status}**\n\n"
        f"## Description\n\n{challenge.get('description', '')}\n\n"
        f"## Solution steps (replayable command log)\n\n"
        f"{_ops_md(records)}\n"
        f"## Notes\n\n{challenge.get('notes_md', '')}\n\n"
        f"## Flag\n\n`{flag}`\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def export_html(path: str, challenge: Dict[str, Any],
                records: List[Dict[str, Any]]) -> str:
    flag = challenge.get("flag", "")
    flag_html = (f"<span class='flag'>{html.escape(flag)}</span>"
                 if flag else "(not recovered)")
    doc = _TEMPLATE.format(
        title=html.escape(challenge.get("name", "challenge")),
        category=html.escape(challenge.get("category", "")),
        event=html.escape(challenge.get("event", "") or "n/a"),
        binary=html.escape(challenge.get("binary_path", "") or "n/a"),
        created=html.escape(str(challenge.get("created_at", ""))),
        status="SOLVED" if challenge.get("solved") else "in progress",
        description=html.escape(challenge.get("description", "")),
        ops=_ops_html(records),
        notes=html.escape(challenge.get("notes_md", "")),
        flag_html=flag_html,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def export_json(path: str, challenge: Dict[str, Any],
                records: List[Dict[str, Any]]) -> str:
    doc = {
        "tool": "RECT", "version": 1,
        "challenge": challenge,
        "operations": records,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def export_csv(path: str, records: List[Dict[str, Any]]) -> str:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["tool", "operation", "input_summary",
                         "output_summary", "success"])
        for r in records:
            writer.writerow([r.get("tool"), r.get("operation"),
                             r.get("input_summary"), r.get("output_summary"),
                             r.get("success")])
    return path


def export_all(challenge: Dict[str, Any], records: List[Dict[str, Any]],
               directory: str) -> Dict[str, str]:
    os.makedirs(directory, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_"
                   for c in challenge.get("name", "challenge"))[:40] or "challenge"
    base = os.path.join(directory, f"rect_{safe}")
    return {
        "markdown": export_markdown(base + ".md", challenge, records),
        "html": export_html(base + ".html", challenge, records),
        "json": export_json(base + ".json", challenge, records),
        "csv": export_csv(base + "_ops.csv", records),
    }
