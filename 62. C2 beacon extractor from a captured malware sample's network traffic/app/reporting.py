"""Shared report model and exporters.

Every workbench in the suite builds a :class:`Report` (verdict + summary +
sections + IOCs) and hands it to the exporters here, which can emit:

  * ``.html`` - standalone, styled, self-contained (open in any browser)
  * ``.json`` - machine readable, full fidelity
  * ``.csv``  - tidy multi-block export for spreadsheets
  * ``.md``   - Markdown for tickets / wikis
  * ``.pdf``  - rendered through Qt (``QTextDocument`` -> ``QPdfWriter``)

Exports are written wherever the caller asks; the UI uses a native save dialog
so the artefact can be saved / downloaded anywhere on disk.
"""
from __future__ import annotations

import csv
import datetime as _dt
import html
import io
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.config import APP, exports_dir, reports_dir

VERDICT_COLORS = {
    "malicious": "#e5484d",
    "critical": "#e5484d",
    "ransomware": "#e5484d",
    "high": "#e5484d",
    "suspicious": "#f5a524",
    "medium": "#f5a524",
    "warning": "#f5a524",
    "beacon": "#f5a524",
    "likely clean": "#30a46c",
    "clean": "#30a46c",
    "benign": "#30a46c",
    "low": "#30a46c",
    "info": "#8b8d98",
    "unknown": "#8b8d98",
}


def verdict_color(verdict: str) -> str:
    return VERDICT_COLORS.get((verdict or "").strip().lower(), "#8b8d98")


def _now() -> _dt.datetime:
    return _dt.datetime.now()


# --------------------------------------------------------------------------- #
#  Model
# --------------------------------------------------------------------------- #
@dataclass
class Section:
    """One block of a report: key/value pairs, a table, or free text."""

    title: str
    kind: str = "kv"  # kv | table | text | code | list
    data: dict = field(default_factory=dict)
    columns: list[str] = field(default_factory=list)
    rows: list[list] = field(default_factory=list)
    text: str = ""
    items: list[str] = field(default_factory=list)
    note: str = ""

    def is_empty(self) -> bool:
        if self.kind == "kv":
            return not self.data
        if self.kind == "table":
            return not self.rows
        if self.kind == "list":
            return not self.items
        return not self.text

    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "kind": self.kind,
            "data": {str(k): str(v) for k, v in self.data.items()},
            "columns": [str(c) for c in self.columns],
            "rows": [[_cell(v) for v in row] for row in self.rows],
            "text": self.text,
            "items": [str(i) for i in self.items],
            "note": self.note,
        }


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".") if value not in (0.0,) else "0"
    return str(value)


@dataclass
class Report:
    """Canonical report container produced by every analysis run."""

    title: str
    subtitle: str = ""
    verdict: str = ""
    risk_score: int | None = None
    summary: str = ""
    sections: list[Section] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    generated_at: _dt.datetime = field(default_factory=_now)
    run_id: str = ""

    # ------------------------------------------------------------- building
    def add_kv(self, title: str, data: dict, note: str = "") -> Section:
        sec = Section(title=title, kind="kv", data=dict(data), note=note)
        self.sections.append(sec)
        return sec

    def add_table(
        self, title: str, columns: list[str], rows: list[list], note: str = ""
    ) -> Section:
        sec = Section(
            title=title, kind="table", columns=list(columns), rows=list(rows), note=note
        )
        self.sections.append(sec)
        return sec

    def add_text(self, title: str, text: str, note: str = "") -> Section:
        sec = Section(title=title, kind="text", text=text, note=note)
        self.sections.append(sec)
        return sec

    def add_code(self, title: str, text: str, note: str = "") -> Section:
        sec = Section(title=title, kind="code", text=text, note=note)
        self.sections.append(sec)
        return sec

    def add_list(self, title: str, items: list[str], note: str = "") -> Section:
        sec = Section(title=title, kind="list", items=[str(i) for i in items], note=note)
        self.sections.append(sec)
        return sec

    def add_ioc_section(self, title: str = "Indicators of Compromise") -> Section | None:
        if not self.iocs:
            return None
        rows = [
            [
                ioc.get("ioc_type", ""),
                ioc.get("value", ""),
                ioc.get("source", ""),
                f"{float(ioc.get('confidence', 0.0)):.2f}",
                ioc.get("context", ""),
            ]
            for ioc in self.iocs
        ]
        return self.add_table(
            title, ["Type", "Value", "Source", "Confidence", "Context"], rows
        )

    # ------------------------------------------------------------ accessors
    def fingerprint(self) -> str:
        """Stable-ish identity used to avoid re-rendering identical reports."""
        body = self.to_dict()
        body.pop("generated_at", None)
        return f"{self.title}|{self.verdict}|{len(self.sections)}|{hash(json.dumps(body, sort_keys=True, default=str))}"

    def default_stem(self) -> str:
        stamp = self.generated_at.strftime("%Y%m%d_%H%M%S")
        base = self.run_id or self.title
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_") or "report"
        return f"{safe}_{stamp}"

    def to_dict(self) -> dict:
        return {
            "app": {
                "name": APP["name"],
                "acronym": APP["acronym"],
                "version": APP["version"],
            },
            "title": self.title,
            "subtitle": self.subtitle,
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "run_id": self.run_id,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "meta": {str(k): _cell(v) for k, v in self.meta.items()},
            "artifacts": list(self.artifacts),
            "iocs": [dict(i) for i in self.iocs],
            "sections": [s.as_dict() for s in self.sections],
        }


# --------------------------------------------------------------------------- #
#  Exporters
# --------------------------------------------------------------------------- #
def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_html(report: Report, for_pdf: bool = False) -> str:
    """Standalone styled HTML.  ``for_pdf`` emits the simplified dialect that
    ``QTextDocument`` can render when producing a PDF."""
    color = verdict_color(report.verdict)
    parts: list[str] = []
    esc = html.escape

    if for_pdf:
        parts.append(
            "<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:9pt;color:#111;'>"
        )
        parts.append(f"<h1 style='margin:0 0 2px 0;'>{esc(report.title)}</h1>")
        if report.subtitle:
            parts.append(f"<p style='margin:0;color:#555;'>{esc(report.subtitle)}</p>")
        parts.append(
            "<p style='margin:2px 0 10px 0;color:#555;'>Generated "
            f"{report.generated_at:%Y-%m-%d %H:%M:%S} &middot; {esc(APP['name'])} "
            f"v{esc(APP['version'])}</p>"
        )
        if report.verdict:
            parts.append(
                "<table width='100%' cellpadding='6' style='background:#eee;'>"
                f"<tr><td><b>Verdict:</b> <span style='color:{color};'><b>{esc(report.verdict)}</b></span>"
                + (
                    f" &nbsp;&nbsp;<b>Risk score:</b> {report.risk_score}"
                    if report.risk_score is not None
                    else ""
                )
                + "</td></tr></table>"
            )
        if report.summary:
            parts.append(f"<p>{esc(report.summary)}</p>")
        if report.meta:
            parts.append("<h2>Overview</h2><table width='100%' cellpadding='3'>")
            for k, v in report.meta.items():
                parts.append(
                    f"<tr><td width='35%'><b>{esc(str(k))}</b></td><td>{esc(_cell(v))}</td></tr>"
                )
            parts.append("</table>")
    else:
        parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
        parts.append(f"<title>{esc(report.title)}</title><style>")
        parts.append(
            """
:root { color-scheme: light; }
body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #17181c; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 28px 64px; background: #fff;
        box-shadow: 0 0 0 1px #e3e5e9; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin: 28px 0 8px; font-size: 17px; border-bottom: 1px solid #e3e5e9; padding-bottom: 6px; }
.sub { color: #5d6069; margin: 0 0 4px; }
.stamp { color: #8b8d98; font-size: 12px; margin-bottom: 18px; }
.banner { display: flex; align-items: center; gap: 14px; padding: 14px 16px; border-radius: 10px;
          background: #f2f3f5; border-left: 6px solid %(color)s; margin: 18px 0; }
.banner .verdict { font-size: 18px; font-weight: 700; color: %(color)s; }
.banner .score { margin-left: auto; font-size: 13px; color: #5d6069; }
table { border-collapse: collapse; width: 100%%; margin: 10px 0 4px; font-size: 13px; }
th, td { border: 1px solid #e3e5e9; padding: 6px 9px; text-align: left; vertical-align: top; }
th { background: #f2f3f5; font-weight: 600; }
tr:nth-child(even) td { background: #fafbfc; }
code, pre { font-family: 'Cascadia Mono', Consolas, monospace; font-size: 12px; }
pre { background: #f6f7f9; border: 1px solid #e3e5e9; border-radius: 8px; padding: 12px;
      overflow-x: auto; white-space: pre-wrap; }
.note { color: #8b8d98; font-size: 12px; margin: 0 0 8px; }
ul { margin: 6px 0 6px 18px; padding: 0; }
.summary { background: #f2f3f5; border-radius: 10px; padding: 12px 14px; margin: 16px 0; }
.foot { margin-top: 36px; padding-top: 12px; border-top: 1px solid #e3e5e9; color: #8b8d98; font-size: 12px; }
@media print { .wrap { box-shadow: none; max-width: none; } }
"""
            % {"color": color}
        )
        parts.append("</style></head><body><div class='wrap'>")
        parts.append(f"<h1>{esc(report.title)}</h1>")
        if report.subtitle:
            parts.append(f"<p class='sub'>{esc(report.subtitle)}</p>")
        parts.append(
            f"<div class='stamp'>Generated {report.generated_at:%Y-%m-%d %H:%M:%S} &middot; "
            f"{esc(APP['name'])} v{esc(APP['version'])}"
            + (f" &middot; run {esc(report.run_id)}" if report.run_id else "")
            + "</div>"
        )
        if report.verdict:
            parts.append("<div class='banner'>")
            parts.append(f"<span class='verdict'>{esc(report.verdict)}</span>")
            if report.risk_score is not None:
                parts.append(f"<span class='score'>Risk score: {report.risk_score}</span>")
            parts.append("</div>")
        if report.summary:
            parts.append(f"<div class='summary'>{esc(report.summary)}</div>")

    # ---- shared body -------------------------------------------------------
    if for_pdf:
        if report.iocs:
            parts.append("<h2>Indicators of Compromise</h2>")
            parts.append("<table width='100%' cellpadding='3' cellspacing='0' border='1'>")
            parts.append("<tr><th>Type</th><th>Value</th><th>Source</th><th>Conf.</th></tr>")
            for ioc in report.iocs:
                parts.append(
                    "<tr><td>{}&nbsp;</td><td>{}&nbsp;</td><td>{}&nbsp;</td><td>{:.2f}&nbsp;</td></tr>".format(
                        esc(str(ioc.get("ioc_type", ""))),
                        esc(str(ioc.get("value", ""))),
                        esc(str(ioc.get("source", ""))),
                        float(ioc.get("confidence", 0.0)),
                    )
                )
            parts.append("</table>")

    for sec in report.sections:
        if sec.is_empty():
            continue
        if for_pdf:
            parts.append(f"<h2>{esc(sec.title)}</h2>")
            if sec.note:
                parts.append(f"<p style='color:#666;'>{esc(sec.note)}</p>")
            if sec.kind == "kv":
                parts.append("<table width='100%' cellpadding='3' border='1'>")
                for k, v in sec.data.items():
                    parts.append(
                        f"<tr><td width='35%'><b>{esc(str(k))}</b></td><td>{esc(_cell(v))}&nbsp;</td></tr>"
                    )
                parts.append("</table>")
            elif sec.kind == "table":
                parts.append("<table width='100%' cellpadding='3' border='1'><tr>")
                for c in sec.columns:
                    parts.append(f"<th>{esc(str(c))}</th>")
                parts.append("</tr>")
                for row in sec.rows:
                    parts.append("<tr>")
                    for cell in row:
                        parts.append(f"<td>{esc(_cell(cell))}&nbsp;</td>")
                    parts.append("</tr>")
                parts.append("</table>")
            elif sec.kind == "list":
                parts.append("<ul>")
                for item in sec.items:
                    parts.append(f"<li>{esc(str(item))}</li>")
                parts.append("</ul>")
            else:
                parts.append(f"<pre>{esc(sec.text)}</pre>")
            continue

        parts.append(f"<h2>{esc(sec.title)}</h2>")
        if sec.note:
            parts.append(f"<p class='note'>{esc(sec.note)}</p>")
        if sec.kind == "kv":
            parts.append("<table>")
            for k, v in sec.data.items():
                parts.append(f"<tr><th>{esc(str(k))}</th><td>{esc(_cell(v))}</td></tr>")
            parts.append("</table>")
        elif sec.kind == "table":
            parts.append("<table><thead><tr>")
            for c in sec.columns:
                parts.append(f"<th>{esc(str(c))}</th>")
            parts.append("</tr></thead><tbody>")
            for row in sec.rows:
                parts.append("<tr>")
                for cell in row:
                    parts.append(f"<td>{esc(_cell(cell))}</td>")
                parts.append("</tr>")
            parts.append("</tbody></table>")
        elif sec.kind == "list":
            parts.append("<ul>")
            for item in sec.items:
                parts.append(f"<li>{esc(str(item))}</li>")
            parts.append("</ul>")
        elif sec.kind == "code":
            parts.append(f"<pre><code>{esc(sec.text)}</code></pre>")
        else:
            for para in sec.text.split("\n\n"):
                parts.append(f"<p>{esc(para)}</p>")

    parts.append(
        f"<div class='foot'>{esc(APP['name'])} v{esc(APP['version'])} &middot; "
        f"{esc(APP['vendor'])} &middot; generated {report.generated_at:%Y-%m-%d %H:%M:%S}</div>"
    )
    if for_pdf:
        parts.append("</body></html>")
    else:
        parts.append("</div></body></html>")
    return "\n".join(parts)


def to_markdown(report: Report) -> str:
    out: list[str] = [f"# {report.title}"]
    if report.subtitle:
        out.append(f"_{report.subtitle}_")
    out.append("")
    out.append(f"**Generated:** {report.generated_at:%Y-%m-%d %H:%M:%S}  ")
    out.append(f"**Tool:** {APP['name']} v{APP['version']}")
    if report.run_id:
        out.append(f"**Run:** `{report.run_id}`")
    out.append("")
    if report.verdict:
        out.append(f"## Verdict: **{report.verdict}**")
        if report.risk_score is not None:
            out.append(f"Risk score: `{report.risk_score}`")
        out.append("")
    if report.summary:
        out.append(report.summary)
        out.append("")

    if report.meta:
        out.append("## Overview")
        out.append("")
        out.append("| Field | Value |")
        out.append("| --- | --- |")
        for k, v in report.meta.items():
            out.append(f"| {k} | {_md(_cell(v))} |")
        out.append("")

    if report.iocs:
        out.append("## Indicators of Compromise")
        out.append("")
        out.append("| Type | Value | Source | Confidence |")
        out.append("| --- | --- | --- | --- |")
        for ioc in report.iocs:
            out.append(
                f"| {_md(str(ioc.get('ioc_type','')))} | `{_md(str(ioc.get('value','')))}` | "
                f"{_md(str(ioc.get('source','')))} | {float(ioc.get('confidence',0.0)):.2f} |"
            )
        out.append("")

    for sec in report.sections:
        if sec.is_empty():
            continue
        out.append(f"## {sec.title}")
        if sec.note:
            out.append(f"_{sec.note}_")
        out.append("")
        if sec.kind == "kv":
            out.append("| Field | Value |")
            out.append("| --- | --- |")
            for k, v in sec.data.items():
                out.append(f"| {k} | {_md(_cell(v))} |")
        elif sec.kind == "table":
            out.append("| " + " | ".join(str(c) for c in sec.columns) + " |")
            out.append("| " + " | ".join("---" for _ in sec.columns) + " |")
            for row in sec.rows:
                out.append("| " + " | ".join(_md(_cell(c)) for c in row) + " |")
        elif sec.kind == "list":
            for item in sec.items:
                out.append(f"- {item}")
        elif sec.kind == "code":
            out.append("```")
            out.append(sec.text)
            out.append("```")
        else:
            out.append(sec.text)
        out.append("")
    return "\n".join(out)


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_csv(report: Report, iocs_only: bool = False) -> str:
    """Tidy multi-block CSV: each section gets a header comment and its own
    table, separated by a blank line.  Opens cleanly in Excel/LibreOffice."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")

    if not iocs_only:
        w.writerow(["# Report", report.title])
        w.writerow(["# Subtitle", report.subtitle])
        w.writerow(["# Generated", report.generated_at.isoformat(timespec="seconds")])
        w.writerow(["# Verdict", report.verdict])
        w.writerow(["# Risk score", report.risk_score if report.risk_score is not None else ""])
        w.writerow(["# Tools", f"{APP['name']} v{APP['version']}"])
        w.writerow([])
        if report.summary:
            w.writerow(["# Summary", report.summary])
            w.writerow([])
        if report.meta:
            w.writerow(["# Overview"])
            w.writerow(["Field", "Value"])
            for k, v in report.meta.items():
                w.writerow([k, _cell(v)])
            w.writerow([])

    w.writerow(["# Indicators of Compromise"])
    w.writerow(["ioc_type", "value", "source", "confidence", "context"])
    for ioc in report.iocs:
        w.writerow(
            [
                ioc.get("ioc_type", ""),
                ioc.get("value", ""),
                ioc.get("source", ""),
                f"{float(ioc.get('confidence', 0.0)):.2f}",
                ioc.get("context", ""),
            ]
        )
    if iocs_only:
        return buf.getvalue()

    for sec in report.sections:
        if sec.is_empty():
            continue
        w.writerow([])
        w.writerow([f"# Section: {sec.title}"])
        if sec.note:
            w.writerow(["# note", sec.note])
        if sec.kind == "kv":
            w.writerow(["Field", "Value"])
            for k, v in sec.data.items():
                w.writerow([k, _cell(v)])
        elif sec.kind == "table":
            w.writerow([str(c) for c in sec.columns])
            for row in sec.rows:
                w.writerow([_cell(c) for c in row])
        elif sec.kind == "list":
            w.writerow(["item"])
            for item in sec.items:
                w.writerow([item])
        else:
            w.writerow(["text"])
            for line in sec.text.splitlines():
                w.writerow([line])
    return buf.getvalue()


def to_pdf(report: Report, path: str | os.PathLike) -> Path:
    """Render the report to PDF using Qt's document/PDF writer (no extra deps)."""
    from PySide6.QtCore import QMarginsF, QSizeF
    from PySide6.QtGui import QPageSize, QPdfWriter, QTextDocument

    html_text = to_html(report, for_pdf=True)
    doc = QTextDocument()
    doc.setHtml(html_text)

    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setResolution(96)
    writer.setPageMargins(QMarginsF(12, 12, 12, 12))
    page_w = writer.width() or 794
    page_h = writer.height() or 1123
    doc.setPageSize(QSizeF(page_w, page_h))

    printer = getattr(doc, "print_", None) or getattr(doc, "print", None)
    if printer is None:  # pragma: no cover - safety net
        raise RuntimeError("QTextDocument printing is unavailable in this Qt build")
    printer(writer)
    return Path(path)


# --------------------------------------------------------------------------- #
#  High level helpers used by the UI
# --------------------------------------------------------------------------- #
FORMATS: list[tuple[str, str, str]] = [
    ("HTML report", "html", "*.html"),
    ("PDF report", "pdf", "*.pdf"),
    ("JSON (full fidelity)", "json", "*.json"),
    ("CSV (tables + IOCs)", "csv", "*.csv"),
    ("IOC list only (CSV)", "iocs.csv", "*.csv"),
    ("Markdown", "md", "*.md"),
]

ALL_EXTENSIONS = ("html", "pdf", "json", "csv", "md")


def export_report(report: Report, path: str | os.PathLike, fmt: str) -> Path:
    """Write ``report`` to ``path`` in the requested format. Returns the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fmt = (fmt or target.suffix.lstrip(".") or "html").lower()

    if fmt == "html":
        target.write_text(to_html(report), encoding="utf-8")
    elif fmt == "json":
        target.write_text(to_json(report), encoding="utf-8")
    elif fmt == "csv":
        target.write_text(to_csv(report), encoding="utf-8", newline="")
    elif fmt == "iocs.csv":
        target.write_text(to_csv(report, iocs_only=True), encoding="utf-8", newline="")
    elif fmt == "md":
        target.write_text(to_markdown(report), encoding="utf-8")
    elif fmt == "pdf":
        to_pdf(report, target)
    else:
        raise ValueError(f"Unsupported export format: {fmt}")
    return target


def export_all(report: Report, directory: str | os.PathLike | None = None) -> list[Path]:
    """Write every format into ``directory`` (default: <data>/exports)."""
    out_dir = Path(directory) if directory else exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = report.default_stem()
    written: list[Path] = []
    for ext in ALL_EXTENSIONS:
        try:
            written.append(export_report(report, out_dir / f"{stem}.{ext}", ext))
        except Exception:
            continue
    return written


def suggested_path(report: Report, fmt: str) -> Path:
    ext = "csv" if fmt in ("csv", "iocs.csv") else fmt
    name = report.default_stem()
    if fmt == "iocs.csv":
        name += "_iocs"
    return reports_dir() / f"{name}.{ext}"
