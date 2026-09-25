"""Normalize raw log lines onto the common schema.

Parser chain (first match wins): JSON → Syslog → Common Log/Combined →
CEF → Key=Value → Plain text. Log content is treated as untrusted input:
strict regexes, try/except everywhere, no eval.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

from .events import NormalizedEvent, RawEvent

# ---------------------------------------------------------------------------
# Severity inference
# ---------------------------------------------------------------------------

_SEV_KEYWORDS = [
    (r"\b(critical|fatal|emerg|panic)\b", "CRITICAL"),
    (r"\b(error|err|fail(ed|ure)?|denied|refused|alert)\b", "ERROR"),
    (r"\b(warn|warning)\b", "WARNING"),
    (r"\bdebug\b", "DEBUG"),
]
_SEV_PATTERNS = [(re.compile(p), s) for p, s in _SEV_KEYWORDS]


def infer_severity(text: str) -> str:
    for pattern, sev in _SEV_PATTERNS:
        if pattern.search(text):
            return sev
    return "INFO"


def _to_float_ts(value: Any) -> Optional[float]:
    """Best-effort epoch from numeric or ISO-ish strings; None if unsure."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            return float(s)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return time.mktime(time.strptime(s[:19], fmt))
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

class JSONParser:
    name = "json"

    def parse(self, raw: str, source_name: str, now: float) -> Optional[NormalizedEvent]:
        line = raw.strip()
        if not (line.startswith("{") and line.endswith("}")):
            return None
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        sev_raw = data.get("severity", data.get("level", data.get("loglevel")))
        severity = str(sev_raw).upper() if sev_raw else infer_severity(raw)
        if severity not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            severity = infer_severity(raw)
        ts = _to_float_ts(data.get("timestamp", data.get("time", data.get("@timestamp")))) or now
        host = str(data.get("host", data.get("hostname", source_name))) or source_name
        fields = {k: v for k, v in data.items() if k not in ("message", "msg")}
        return NormalizedEvent(
            ts=ts, source=source_name, source_type="json", host=host,
            severity=severity, message=raw, fields=fields, raw=raw,
        )


_SYSLOG_RE = re.compile(
    r"^<(\d{1,3})>\s*"
    r"(?:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2})?)"  # RFC5424 ts
    r"|([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"  # RFC3164 ts
    r"\s+(?:(\S+)\s+)?(\S+)"  # optional host, then tag/program
    r"(?:\[(\d+)\])?\s*:\s?(.*)$",
    re.DOTALL,
)
_PRI_SEV = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR", 4: "WARNING",
            5: "INFO", 6: "INFO", 7: "DEBUG"}


class SyslogParser:
    name = "syslog"

    def parse(self, raw: str, source_name: str, now: float) -> Optional[NormalizedEvent]:
        m = _SYSLOG_RE.match(raw.strip())
        if not m:
            return None
        pri = int(m.group(1))
        rfc5424_ts, rfc3164_ts, host, tag, pid, msg = m.groups()
        ts = now
        if rfc5424_ts:
            ts = _to_float_ts(rfc5424_ts) or now
        elif rfc3164_ts:
            try:
                ts = time.mktime(time.strptime(rfc3164_ts, "%b %d %H:%M:%S"))
                # RFC3164 has no year; assume current year, clamp into the past.
                if ts > now + 86400:
                    ts -= 366 * 86400
            except ValueError:
                ts = now
        severity = _PRI_SEV.get(pri & 0x07, "INFO")
        fields: dict[str, Any] = {"facility": (pri >> 3) & 0x1F, "priority": pri}
        if pid:
            fields["pid"] = pid
        return NormalizedEvent(
            ts=ts, source=source_name, source_type="syslog",
            host=host or source_name, severity=severity,
            message=msg or raw, fields=fields, raw=raw,
        )


_CLF_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?$'
)


class CommonLogParser:
    name = "commonlog"

    def parse(self, raw: str, source_name: str, now: float) -> Optional[NormalizedEvent]:
        m = _CLF_RE.match(raw.strip())
        if not m:
            return None
        ip, ident, user, when, request, status, size, referer, ua = m.groups()
        ts = now
        try:
            ts = time.mktime(time.strptime(when, "%d/%b/%Y:%H:%M:%S %z"))
        except ValueError:
            try:
                ts = time.mktime(time.strptime(when, "%d/%b/%Y:%H:%M:%S"))
            except ValueError:
                pass
        fields = {
            "src_ip": ip,
            "user": user if user != "-" else "",
            "request": request,
            "status": status,
            "bytes": size if size != "-" else "",
            "referer": referer or "",
            "user_agent": ua or "",
        }
        return NormalizedEvent(
            ts=ts, source=source_name, source_type="commonlog", host=ip,
            severity=infer_severity(raw), message=raw, fields=fields, raw=raw,
        )


_CEF_HEAD_RE = re.compile(
    r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$",
    re.DOTALL,
)
_CEF_SEV = {0: "INFO", 1: "INFO", 2: "INFO", 3: "WARNING", 4: "WARNING",
            5: "WARNING", 6: "ERROR", 7: "ERROR", 8: "CRITICAL", 9: "CRITICAL", 10: "CRITICAL"}


class CEFParser:
    name = "cef"

    def parse(self, raw: str, source_name: str, now: float) -> Optional[NormalizedEvent]:
        m = _CEF_HEAD_RE.match(raw.strip())
        if not m:
            return None
        ver, vendor, product, pver, sig, name, sev, rest = m.groups()
        fields: dict[str, Any] = {
            "cef_version": ver, "vendor": vendor, "product": product,
            "product_version": pver, "signature_id": sig, "cef_name": name,
        }
        for pair in rest.split():
            if "=" in pair:
                k, _, v = pair.partition("=")
                v = v.strip('"')
                if k:
                    fields[k] = v
        sev_num = 0
        try:
            sev_num = int(sev)
        except ValueError:
            pass
        severity = _CEF_SEV.get(sev_num, "INFO")
        return NormalizedEvent(
            ts=now, source=source_name, source_type="cef",
            host=fields.get("src", fields.get("dhost", source_name)),
            severity=severity, message=raw, fields=fields, raw=raw,
        )


_KVP_RE = re.compile(r"(?<![\w-])([A-Za-z_][A-Za-z0-9_.-]*)=(\"[^\"]*\"|\S+)")


class KVPParser:
    name = "kvp"

    def parse(self, raw: str, source_name: str, now: float) -> Optional[NormalizedEvent]:
        line = raw.strip()
        pairs = _KVP_RE.findall(line)
        if len(pairs) < 2:
            return None
        fields = {k: v.strip('"') for k, v in pairs}
        return NormalizedEvent(
            ts=now, source=source_name, source_type="kvp",
            host=fields.get("host", fields.get("hostname", source_name)),
            severity=infer_severity(raw), message=raw, fields=fields, raw=raw,
        )


class PlainParser:
    name = "plain"

    def parse(self, raw: str, source_name: str, now: float) -> NormalizedEvent:
        return NormalizedEvent(
            ts=now, source=source_name, source_type="plain",
            host=source_name, severity=infer_severity(raw),
            message=raw, fields={}, raw=raw,
        )


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Auto-detects the log format and produces NormalizedEvents."""

    def __init__(self) -> None:
        self.parsers = [
            JSONParser(),
            SyslogParser(),
            CommonLogParser(),
            CEFParser(),
            KVPParser(),
            PlainParser(),
        ]

    def normalize(self, raw: RawEvent) -> NormalizedEvent:
        for parser in self.parsers:
            try:
                ev = parser.parse(raw.raw, raw.source_name, raw.ts)
            except Exception:
                ev = None
            if ev is not None:
                return ev
        # Unreachable in practice (PlainParser never fails), kept as a guard.
        return PlainParser().parse(raw.raw, raw.source_name, raw.ts)