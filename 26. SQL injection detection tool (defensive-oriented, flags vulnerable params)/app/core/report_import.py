"""Findings-file parser for manual import (SIDT)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_TECHNIQUES = {"error", "boolean", "time", "union"}


def parse_findings_doc(doc: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Accepts {scan: {...}, findings: [...]} or a bare list of findings."""
    if isinstance(doc, list):
        raw, meta = doc, {"target": "imported", "notes": "bare list import"}
    elif isinstance(doc, dict):
        raw = doc.get("findings", [])
        meta = dict(doc.get("scan", {}) or {})
        meta.setdefault("target", doc.get("target", "imported"))
        meta.setdefault("started_at", doc.get("started_at", ""))
        meta.setdefault("finished_at", doc.get("finished_at", ""))
    else:
        return [], {}

    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        f = dict(item)
        sev = str(f.get("severity", "medium")).lower()
        f["severity"] = sev if sev in VALID_SEVERITIES else "medium"
        tech = str(f.get("technique", "error")).lower()
        f["technique"] = tech if tech in VALID_TECHNIQUES else "error"
        conf = str(f.get("confidence", "medium")).lower()
        f["confidence"] = conf if conf in {"high", "medium", "low"} else "medium"
        try:
            f["status"] = int(f.get("status", 0) or 0)
        except (TypeError, ValueError):
            f["status"] = 0
        try:
            f["resp_time_ms"] = float(f.get("resp_time_ms", 0) or 0.0)
        except (TypeError, ValueError):
            f["resp_time_ms"] = 0.0
        out.append(f)
    return out, meta
