"""Findings-file parser for manual import (XPT)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_TYPES = {"reflected", "stored", "dom"}
VALID_CONTEXTS = {"html_body", "html_attribute", "js_string", "url_param",
                  "css_context", "unknown"}


def parse_findings_doc(doc: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
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
        t = str(f.get("xss_type", "reflected")).lower()
        f["xss_type"] = t if t in VALID_TYPES else "reflected"
        ctx = str(f.get("context", "unknown")).lower()
        f["context"] = ctx if ctx in VALID_CONTEXTS else "unknown"
        conf = str(f.get("confidence", "medium")).lower()
        f["confidence"] = conf if conf in {"high", "medium", "low"} else "medium"
        f["browser_confirmed"] = bool(f.get("browser_confirmed", False))
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
