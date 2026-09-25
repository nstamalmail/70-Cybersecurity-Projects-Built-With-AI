"""Reflection analysis for XPT: locate the payload in the response, classify
context and encoding (architecture.md §3.3 Reflection Analyzer).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from app.core.payloads import MARKER

_RAW_CHARS = ("<", ">", '"', "'", "`")


@dataclass
class ReflectionResult:
    reflected: bool
    raw: bool                       # dangerous characters appear unencoded
    context: str                    # html_body / html_attribute / js_string / ...
    encoding_applied: str           # 'none' / 'html_encoded' / 'url_encoded' / 'partial'
    snippet: str = ""


def classify_context(body: str, pos: int) -> str:
    """Classify the injection context around the reflection position."""
    before = body[max(0, pos - 300):pos]
    # Deepest context wins: script > style > attribute > body
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script>")
    if last_script_open > last_script_close:
        return "js_string"
    last_style_open = before.rfind("<style")
    last_style_close = before.rfind("</style>")
    if last_style_open > last_style_close:
        return "css_context"
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        tag_body = before[last_lt:]
        if re.search(r"=\s*[\"']?[^\"']*$", tag_body):
            return "html_attribute"
    return "html_body"


def _is_raw(fragment: str) -> bool:
    """True when fragment still contains structure-breaking characters.

    Only < > " count as structure-breaking in HTML contexts: a server that
    html-encodes those blocks tag/attribute injection, while a lone ' (often
    left unencoded) cannot break out of a double-quoted attribute.
    """
    return any(c in fragment for c in ("<", ">", '"'))


def _is_html_encoded(fragment: str) -> bool:
    low = fragment.lower()
    return "&lt;" in low or "&gt;" in low or "&quot;" in low or "&#x3c" in low


def analyze_reflection(payload: str, body: str) -> ReflectionResult:
    """Locate payload (or marker) reflection in `body` and classify it."""
    # 1) direct payload reflection
    idx = body.find(payload)
    if idx != -1:
        start, end = idx, idx + len(payload)
        fragment = payload
        encoding = "none" if _is_raw(payload) else (
            "html_encoded" if _is_html_encoded(payload) else "partial")
        raw = _is_raw(payload)
        ctx = classify_context(body, start)
        window = body[max(0, start - 160): end + 240]
        return ReflectionResult(True, raw, ctx, encoding, window)

    # 2) marker-based reflection (payloads embedding the marker)
    marker_idx = body.find(MARKER)
    if marker_idx != -1:
        # Find the encoded boundary of the injected value: expand from the
        # marker outwards while we remain inside the reflected fragment
        # (delimited by the page's own '<' / '>' structure).
        start = marker_idx
        while start > 0 and body[start - 1] not in (">", "<"):
            start -= 1
        end = marker_idx
        while end < len(body) and body[end] not in ("<", ">"):
            end += 1
        # The value region sits between page structure; decode-compare it
        value_region = body[start:end]
        raw = _is_raw(value_region)
        encoding = "none" if raw else (
            "html_encoded" if _is_html_encoded(value_region) else "partial")
        ctx = classify_context(body, marker_idx)
        window = body[max(0, marker_idx - 160): marker_idx + 240]
        return ReflectionResult(True, raw, ctx, encoding, window)

    # 3) url-decoded reflection
    dec = urllib.parse.unquote(body)
    idx = dec.find(payload)
    if idx != -1 and payload:
        raw = _is_raw(payload)
        ctx = classify_context(dec, idx)
        window = dec[max(0, idx - 160): idx + len(payload) + 240]
        encoding = "url_encoded" if raw else "partial"
        return ReflectionResult(True, raw, ctx, encoding, window)

    return ReflectionResult(False, False, "unknown", "none")


def execution_risk(reflection: ReflectionResult, payload: str) -> bool:
    """Heuristic: does this raw reflection likely execute in browser?"""
    if not reflection.reflected or not reflection.raw:
        return False
    low = payload.lower()
    if "script" in low or "onerror" in low or "onload" in low or "ontoggle" in low \
            or "onmouseover" in low or "onfocus" in low or "javascript:" in low \
            or "alert(" in low:
        return True
    return reflection.context in ("js_string", "html_attribute")
