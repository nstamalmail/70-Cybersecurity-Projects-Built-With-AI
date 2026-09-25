"""Findings-file parser for manual import (CBSEF)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.core.models import STATUSES, CONFIDENCE_LEVELS, TEST_CASES, new_finding_id


def parse_findings_doc(doc: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Accepts {session: {...}, findings: [...]} or a bare list of findings."""
    if isinstance(doc, list):
        raw, meta = doc, {"name": "imported session"}
    elif isinstance(doc, dict):
        raw = doc.get("findings", [])
        meta = dict(doc.get("session", {}) or {})
        meta.setdefault("name", doc.get("name", "imported session"))
    else:
        return [], {}

    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        f = dict(item)
        f["finding_id"] = str(f.get("finding_id") or new_finding_id())
        tc = str(f.get("test_case", "mass_assignment"))
        f["test_case"] = tc if tc in TEST_CASES else "mass_assignment"
        st = str(f.get("status", "candidate")).lower()
        f["status"] = st if st in STATUSES else "candidate"
        conf = str(f.get("confidence", "medium")).lower()
        f["confidence"] = conf if conf in CONFIDENCE_LEVELS else "medium"
        out.append(f)
    return out, meta
