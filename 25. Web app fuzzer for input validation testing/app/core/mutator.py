"""Payload encoders.

String/URL encoding is applied to the *payload value* before it is inserted into
the injection point. Detectors decode the response where needed (extract_result).
"""

from __future__ import annotations

import base64
import re
from typing import Callable, Dict, List
from urllib.parse import quote, unquote

Encoder = Callable[[str], str]

ENCODINGS = ["none", "url", "double_url", "html_entities", "base64", "unicode"]


def enc_none(p: str) -> str:
    return p


def enc_url(p: str) -> str:
    return quote(p, safe="")


def enc_double_url(p: str) -> str:
    return quote(quote(p, safe=""), safe="")


_HTML_ENTITIES = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
}


def enc_html(p: str) -> str:
    return "".join(_HTML_ENTITIES.get(c, c) for c in p)


def enc_base64(p: str) -> str:
    return base64.b64encode(p.encode("utf-8", errors="ignore")).decode("ascii")


def enc_unicode(p: str) -> str:
    """Percent-encode each byte as %u00XX (common WAF-bypass / IIS style)."""
    out = []
    for b in p.encode("utf-8", errors="ignore"):
        out.append(f"%u00{b:02X}")
    return "".join(out)


ENCODERS: Dict[str, Encoder] = {
    "none": enc_none,
    "url": enc_url,
    "double_url": enc_double_url,
    "html_entities": enc_html,
    "base64": enc_base64,
    "unicode": enc_unicode,
}

_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_DBL_PCT_RE = re.compile(r"%25[0-9A-Fa-f]{2}")


def encoded_payload(raw: str, encoding: str) -> str:
    return ENCODERS.get(encoding, enc_none)(raw)


def extract_result(raw: str, encoding: str) -> str:
    """Reverse the encoder (best effort) so detectors can match decoded content."""
    if encoding == "none":
        return raw
    if encoding == "url":
        return _pct_unquote(raw)
    if encoding == "double_url":
        return _pct_unquote(_pct_unquote(raw))
    if encoding == "html_entities":
        return _html_unescape(raw)
    if encoding == "base64":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="ignore")
        except Exception:
            return raw
    if encoding == "unicode":
        return _pct_unquote(raw.replace("%u00", "%"))
    return raw


def _pct_unquote(s: str) -> str:
    try:
        return unquote(s)
    except Exception:
        return s


def _html_unescape(s: str) -> str:
    for k, v in _HTML_ENTITIES.items():
        s = s.replace(v, k)
    return s


def encoding_label(encoding: str) -> str:
    return {
        "none": "None",
        "url": "URL-encoded",
        "double_url": "Double URL-encoded",
        "html_entities": "HTML entities",
        "base64": "Base64",
        "unicode": "%u unicode",
    }.get(encoding, encoding)


def available_encodings() -> List[str]:
    return list(ENCODINGS)