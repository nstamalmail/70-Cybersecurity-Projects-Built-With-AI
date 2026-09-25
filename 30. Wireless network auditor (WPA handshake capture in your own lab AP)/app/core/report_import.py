"""Audit-file parser for manual import (WNA)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.core.models import COMPLETENESS


def parse_audit_doc(doc: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Accepts {audit: {...}, targets: [...]} or a bare target list."""
    if isinstance(doc, list):
        raw, meta = doc, {"audit_id": "imported", "notes": "bare list import"}
    elif isinstance(doc, dict):
        raw = doc.get("targets", doc.get("findings", []))
        meta = dict(doc.get("audit", {}) or {})
        meta.setdefault("audit_id", doc.get("audit_id", "imported"))
    else:
        return [], {}

    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        t = dict(item)
        comp = str(t.get("handshake_completeness", "none")).lower()
        t["handshake_completeness"] = comp if comp in COMPLETENESS else "none"
        t["handshake_captured"] = bool(t.get("handshake_captured",
                                             comp == "complete"))
        t["pmkid_captured"] = bool(t.get("pmkid_captured", False))
        t["crack_attempted"] = bool(t.get("crack_attempted", False))
        msgs = t.get("messages_present", [])
        if isinstance(msgs, str):
            msgs = [m.strip() for m in msgs.split(",") if m.strip()]
        t["messages_present"] = msgs
        try:
            t["channel"] = int(t.get("channel", 0) or 0)
        except (TypeError, ValueError):
            t["channel"] = 0
        try:
            t["crack_duration_seconds"] = float(
                t.get("crack_duration_seconds", 0) or 0.0)
        except (TypeError, ValueError):
            t["crack_duration_seconds"] = 0.0
        out.append(t)
    return out, meta
