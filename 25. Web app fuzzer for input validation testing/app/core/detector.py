"""Response analysis: turns raw responses into validated findings.

Detectors receive the (already decoded) response body, the response object,
the request spec, and the decoded payload. Baseline inputs (body, status,
elapsed) for the same injection point are used for relative checks.
"""

from __future__ import annotations

import html as _html
import re
from typing import List
from urllib.parse import unquote, urlparse

from app.core.models import Finding, RequestSpec
from app.core.mutator import extract_result

# --- SQL error signatures ---------------------------------------------------
SQL_ERROR_RE = [
    re.compile(r"(you have an error in your sql syntax|mysql_fetch|mysqli|syntax error near)", re.I),
    re.compile(r"(postgresql|psycopg|pg_query|syntax error at or near)", re.I),
    re.compile(r"(microsoft odbc|sql server|unclosed quotation mark|incorrect syntax near)", re.I),
    re.compile(r"(sqlite3|sqlite_error|near \"|\": syntax error)", re.I),
    re.compile(r"(ora-\d{5}|oracle.*error|quoted string not properly terminated)", re.I),
    re.compile(r"(sqlstate\[\d+\]|jdbc|com\.mysql|syntax error .* select)", re.I),
]

FILE_READ_MARKERS = [
    "root:x:0:0:",
    "daemon:x:1:1:",
    "/bin/bash",
    "[fonts]",
    "[extensions]",
    "; for 16-bit app support",
    "[boot loader]",
]

CMD_OUTPUT_MARKERS = [
    re.compile(r"\buid=\d+\(\w+\) gid=\d+", re.I),        # unix id
    re.compile(r"nt authority\\|\bsystem32\\|\bwindows\\system32", re.I),  # windows
]

SSTI_MARKERS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]

BODY_SIZE_CAP = 200_000

_TIME_BASED_RE = re.compile(r"(sleep\s*\(|waitfor\s*delay|pg_sleep\s*\(|benchmark\s*\()", re.I)


def _is_time_based(payload: str) -> bool:
    """True when the payload tries to make the back-end sleep (time-based blind)."""
    return bool(_TIME_BASED_RE.search(payload or ""))


class ResponseAnalyzer:
    """Stateless analysis hub; one instance shared by all workers."""

    def analyze(self, spec: RequestSpec, resp, elapsed: float,
                payload: str, encoding: str, category: str,
                baseline_body: str, baseline_status: int, baseline_elapsed: float,
                injection_kind: str = "", injection_name: str = "") -> List[Finding]:
        """Return findings for one request. May be empty."""
        findings: List[Finding] = []

        try:
            body = resp.text
        except Exception:
            body = ""
        body = body[:BODY_SIZE_CAP]
        body_decoded = _decode_body(body, encoding)
        payload_encoded = payload
        payload_decoded = extract_result(payload, encoding)

        analysis = _Analysis(
            spec=spec, resp=resp, elapsed=elapsed,
            body_raw=body, body_decoded=body_decoded,
            payload_encoded=payload_encoded, payload_decoded=payload_decoded,
            baseline_body=baseline_body, baseline_status=baseline_status,
            baseline_elapsed=baseline_elapsed,
        )
        url = spec.url
        status = resp.status_code if resp is not None else 0
        resp_len = len(body)

        def make(technique: str, severity: str, evidence: str) -> Finding:
            return Finding(
                category=category, technique=technique, severity=severity,
                injection_kind=injection_kind or "",
                injection_name=injection_name or "",
                payload=payload, encoding=encoding, url=url, status=status,
                resp_len=resp_len, resp_time_ms=elapsed * 1000,
                evidence=evidence, request=spec.preview(),
                response=_snippet(body, evidence),
            )

        # 1) SQL error signatures.
        if category == "sqli" and _matches_sql_error(body_decoded):
            findings.append(make("sql-error", "high", _first_sql_error(body_decoded)))

        # 2) Time-based blind.
        if category == "sqli" and _is_time_based(payload) \
                and elapsed >= min(4.0, baseline_elapsed + 3.5):
            findings.append(make("time-based-blind", "high",
                                 f"elapsed {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s"))

        # 3) File-read markers (baseline-relative so normal content is not flagged).
        if category in ("cmdi", "path_traversal", "custom") \
                and _matches_file_read(body_decoded) \
                and not _matches_file_read(analysis.baseline_body):
            findings.append(make("file-read", "critical", _file_read_hit(body_decoded)))

        # 4) Command output markers (baseline-relative).
        if category in ("cmdi", "custom") and _matches_cmd_output(body_decoded) \
                and not _matches_cmd_output(analysis.baseline_body):
            findings.append(make("cmd-output", "high", _cmd_output_hit(body_decoded)))

        # 5) SSTI computed output (baseline-relative).
        if category == "ssti" and _ssti_hit(body_decoded, analysis.baseline_body):
            findings.append(make("ssti-eval", "high", "template evaluated our expression"))

        # 6) Open redirect (Location header; we do not follow redirects for this category).
        if category == "open_redirect" and resp is not None and status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "") or resp.url or ""
            if _attacker_redirect(loc, spec.url):
                findings.append(make("open-redirect", "medium",
                                     f"redirected to: {loc[:200]}"))

        # 7) CRLF header injection (best effort via `requests`; usually blocked).
        if category == "crlf" and resp is not None:
            for k in resp.headers:
                if k.lower() == "x-injected":
                    findings.append(make("crlf-header", "medium",
                                         f"header X-Injected present: {resp.headers[k][:100]}"))

        # 8) XSS reflection with context analysis (match encoded or decoded form).
        if category == "xss":
            reflected_form = _reflected_form(payload_encoded, payload_decoded, body, body_decoded)
            if reflected_form:
                ctx = _context(body_decoded, reflected_form)
                sev = "high" if ctx in ("attribute", "script", "html") else "low"
                findings.append(make("xss-reflection", sev, f"reflected in {ctx} context"))

        # 9) Generic reflection info (for non-XSS payloads that echo back).
        if category not in ("xss", "sqli", "ssti") and _reflected_form(
                payload_encoded, payload_decoded, body, body_decoded):
            findings.append(make("reflection-info", "info", "payload reflected verbatim in response"))

        if len(findings) > 3:
            findings = findings[:3]
        return findings


class _Analysis:
    """Shorthand container to keep method signatures small."""

    def __init__(self, spec, resp, elapsed, body_raw, body_decoded,
                 payload_encoded, payload_decoded, baseline_body,
                 baseline_status, baseline_elapsed):
        self.spec = spec
        self.resp = resp
        self.elapsed = elapsed
        self.body_raw = body_raw
        self.body_decoded = body_decoded
        self.payload_encoded = payload_encoded
        self.payload_decoded = payload_decoded
        self.baseline_body = baseline_body
        self.baseline_status = baseline_status
        self.baseline_elapsed = baseline_elapsed


def _decode_body(body: str, encoding: str) -> str:
    """Best-effort response body decoding for the given encoding.

    Percent/HTML decoding is lossless and safe; Base64/%u bodies cannot be
    reverse-engineered wholesale, so they are returned unchanged (detectors
    also match the encoded payload form directly).
    """
    if encoding == "url":
        try:
            return unquote(body)
        except Exception:
            return body
    if encoding == "double_url":
        try:
            return unquote(unquote(body))
        except Exception:
            return body
    if encoding == "html_entities":
        return _html.unescape(body)
    return body


def _reflected_form(payload_encoded: str, payload_decoded: str,
                    body: str, body_decoded: str) -> str:
    """Return the payload form actually reflected in the response, or ''."""
    if payload_encoded and len(payload_encoded) >= 3 and payload_encoded in body:
        return payload_encoded
    if payload_decoded and len(payload_decoded) >= 3:
        if payload_decoded in body:
            return payload_decoded
        if body_decoded != body and payload_decoded in body_decoded:
            return payload_decoded
    return ""


def _matches_sql_error(body: str) -> bool:
    return any(r.search(body) for r in SQL_ERROR_RE)


def _first_sql_error(body: str) -> str:
    for r in SQL_ERROR_RE:
        m = r.search(body)
        if m:
            return _surround(body, m.start(), 320)
    return "SQL error signature present"


def _matches_file_read(body: str) -> bool:
    return any(marker in body for marker in FILE_READ_MARKERS)


def _file_read_hit(body: str) -> str:
    for marker in FILE_READ_MARKERS:
        idx = body.find(marker)
        if idx >= 0:
            return "file content marker: " + _surround(body, idx, 260)
    return "file content markers present"


def _matches_cmd_output(body: str) -> bool:
    return any(r.search(body) for r in CMD_OUTPUT_MARKERS)


def _cmd_output_hit(body: str) -> str:
    for r in CMD_OUTPUT_MARKERS:
        m = r.search(body)
        if m:
            return "command output: " + _surround(body, m.start(), 260)
    return "command output markers present"


def _ssti_hit(body: str, baseline: str) -> bool:
    for probe, expected in SSTI_MARKERS:
        if expected in body and expected not in baseline:
            return True
    return False


def _attacker_redirect(location: str, original: str) -> bool:
    loc = location.lower()
    if "evil.com" in loc:
        return True
    if "http://" in loc or "https://" in loc:
        host = urlparse(loc).netloc
        orig_host = urlparse(original).netloc
        return host != orig_host
    if loc.startswith("//"):
        return True
    return False


def _context(body: str, needle: str) -> str:
    idx = body.find(needle)
    if idx < 0:
        return "none"
    before = body[max(0, idx - 300): idx]
    after = body[idx + len(needle): idx + len(needle) + 300]

    if "<script" in before[-60:].lower() or "</script>" in after[:60].lower():
        return "script"
    if "=" in before[-20:] or '"' in before[-5:] or "'" in before[-5:]:
        return "attribute"
    if re.search(r"<[a-zA-Z][^>]*>", before[-80:]):
        return "html"
    return "unknown"


def _snippet(body: str, evidence: str) -> str:
    if not evidence:
        return body[:500]
    idx = body.find(evidence)
    if idx < 0:
        return body[:500]
    start = max(0, idx - 120)
    end = min(len(body), idx + len(evidence) + 120)
    return body[start:end]


def _surround(body: str, idx: int, size: int) -> str:
    start = max(0, idx - size // 2)
    end = min(len(body), idx + size // 2)
    return body[start:end].replace("\n", " ")[:size]