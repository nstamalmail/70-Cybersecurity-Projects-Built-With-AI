"""Detection techniques + response analysis for SIDT.

Implements error-based, boolean-based blind, time-based blind and union-based
detection with safe-mode gating (architecture.md §3.3). No destructive
payloads are ever generated; union probes use markers only; time delays are
capped (<= 5s payload, opt-in only).
"""

from __future__ import annotations

import difflib
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from app.core.models import Parameter, ScanConfig

# ---------------------------------------------------------------- DBMS signatures
DBMS_SIGNATURES: Dict[str, List[str]] = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql", "mysql_fetch", "mysqli?", "mariadb",
        "unclosed quotation mark",  # also mssql; refined by context below
        "quoted string not properly terminated",
    ],
    "postgresql": [
        "pg_query", "postgresql", "psql", "unterminated quoted string",
        "syntax error at or near", "warning: pg_",
    ],
    "mssql": [
        "microsoft sql server", "sql server", "odbc sql server driver",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
    ],
    "oracle": [
        "ora-", "oracle error", "quoted string not properly terminated",
    ],
    "sqlite": [
        "sqlite", "sqlite3", "unrecognized token", "near \"\": syntax error",
    ],
}


def fingerprint_dbms(text: str) -> str:
    low = text.lower()
    for dbms, sigs in DBMS_SIGNATURES.items():
        for sig in sigs:
            if sig in low:
                return dbms
    return ""


SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"incorrect syntax near", re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sqlite3?\??\.?\w*Exception", re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"PG::SyntaxError|pg_query\(", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"mysql_fetch_", re.I),
]

WAF_HEADERS = [
    ("server", "cloudflare"), ("server", "cloudflare-nginx"),
    ("x-sucuri-id", None), ("x-sucuri-cache", None),
    ("server", "succuri"), ("x-waf-status", None), ("x-cdn", None),
    ("cf-ray", None), ("x-iinfo", None), ("x-akamai-transformed", None),
    ("x-cnection", None), ("x-mod-pagespeed", None),
]

WAF_BODY_MARKERS = [
    "cloudflare", "sucuri", "akamai", "imperva", "incapsula", "f5 big-ip",
    "blocked by waf", "web application firewall", "request blocked",
    "access denied", "mod_security", "modsecurity",
]

# Safe-mode boolean payloads: true/false pairs, non-destructive.
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
]

ERROR_PAYLOADS: List[str] = [
    "'",
    "\"",
    "')",
    "';",
    "\\",
    "' OR '1'='1",
]

TIME_PAYLOADS: List[str] = [
    "' AND SLEEP({d})-- -",          # MySQL
    "'; WAITFOR DELAY '0:0:{d}'-- -",  # MSSQL
    "' || pg_sleep({d})-- -",          # PostgreSQL
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",  # SQLite (heavy)
]

UNION_MARKERS = ["sidt7f3a", "sidtmark91"]
UNION_PAYLOADS: List[str] = [
    "' UNION SELECT {marker}-- -",
    "' UNION SELECT NULL, {marker}-- -",
    "' UNION SELECT NULL, NULL, {marker}-- -",
    "' UNION SELECT NULL, NULL, NULL, {marker}-- -",
]

DESTRUCTIVE_TOKENS = re.compile(
    r"\b(drop|delete|update|insert|truncate|alter|create)\b", re.I)


def assert_safe(payload: str) -> None:
    """Guard: refuse destructive payloads (architecture.md §6)."""
    m = DESTRUCTIVE_TOKENS.search(payload)
    if m:
        raise ValueError(f"unsafe payload token: {m.group(1)}")


@dataclass
class ResponseData:
    status: int
    body: str
    elapsed_ms: float
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def sig(self) -> Tuple:
        return (self.status, len(self.body),
                hashlib.md5(self.body.encode("utf-8", "ignore")).hexdigest())


@dataclass
class ProbeResult:
    technique: str
    vulnerable: bool
    confidence: str           # high / medium / low
    severity: str
    signal: str
    dbms_hint: str = ""
    payload: str = ""
    baseline_request: str = ""
    injected_request: str = ""
    baseline_response_snippet: str = ""
    injected_response_snippet: str = ""
    response_delta: Dict = field(default_factory=dict)


# ------------------------------------------------------------------ WAF detect
def detect_waf(resp: ResponseData) -> str:
    low = resp.body.lower()
    for h, v in WAF_HEADERS:
        hv = resp.headers.get(h, "").lower()
        if not hv:
            # case-insensitive header lookup
            for hk, hv2 in resp.headers.items():
                if hk.lower() == h:
                    hv = hv2.lower()
                    break
        if v and v in hv:
            return v
        if v is None and hv:
            return h
    for marker in WAF_BODY_MARKERS:
        if marker in low:
            return marker
    return ""


# ------------------------------------------------------------------ analyzers
def analyze_error(baseline: ResponseData, injected: ResponseData) -> Optional[ProbeResult]:
    m = None
    for pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(injected.body)
        if match and not pattern.search(baseline.body):
            m = match
            break
    if not m:
        return None
    dbms = fingerprint_dbms(injected.body[max(0, m.start() - 120): m.end() + 160])
    return ProbeResult(
        technique="error", vulnerable=True, confidence="high", severity="high",
        signal=f"SQL error message in response: {m.group(0)[:90]!r}",
        dbms_hint=dbms, payload="",
        injected_response_snippet=injected.body[max(0, m.start() - 80): m.end() + 200],
        baseline_response_snippet=baseline.body[:400],
        response_delta={"status": injected.status, "baseline_status": baseline.status},
    )


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def analyze_boolean(baseline: ResponseData, true_resp: ResponseData,
                    false_resp: ResponseData, payload_true: str,
                    payload_false: str) -> Optional[ProbeResult]:
    """Boolean-based: TRUE/FALSE responses must differ meaningfully.

    Canonical signature: one side matches the baseline page (valid render)
    while the other diverges; OR-form blind signatures instead show strong
    length divergence between the two condition responses.
    """
    if true_resp.sig == false_resp.sig:
        return None
    diff_tf = 1.0 - _similarity(true_resp.body, false_resp.body)
    if diff_tf < 0.05 or len(true_resp.body) == len(false_resp.body) == 0:
        return None
    true_matches = (true_resp.sig == baseline.sig
                    or _similarity(true_resp.body, baseline.body) > 0.9)
    false_matches = (false_resp.sig == baseline.sig
                     or _similarity(false_resp.body, baseline.body) > 0.9)
    length_divergence = abs(len(true_resp.body) - len(false_resp.body)) >= 8
    if not (true_matches or false_matches or length_divergence):
        return None
    sev = "high" if diff_tf > 0.15 else "medium"
    conf = "high" if (diff_tf > 0.3 or true_matches) else "medium"
    return ProbeResult(
        technique="boolean", vulnerable=True,
        confidence=conf,
        severity=sev,
        signal=(f"TRUE/FALSE condition responses differ "
                f"(similarity {diff_tf:.0%}, len {len(true_resp.body)} vs "
                f"{len(false_resp.body)})"),
        payload=payload_true,
        baseline_response_snippet=baseline.body[:300],
        injected_response_snippet=true_resp.body[:300],
        response_delta={"true_len": len(true_resp.body),
                        "false_len": len(false_resp.body),
                        "baseline_len": len(baseline.body),
                        "diff_ratio": round(diff_tf, 3),
                        "true_matches_baseline": true_matches,
                        "false_matches_baseline": false_matches,
                        "true_payload": payload_true,
                        "false_payload": payload_false},
    )


def analyze_time(baseline: ResponseData, injected: ResponseData,
                 payload: str, threshold_s: float) -> Optional[ProbeResult]:
    base_s = baseline.elapsed_ms / 1000.0
    inj_s = injected.elapsed_ms / 1000.0
    if inj_s >= threshold_s and inj_s > base_s + threshold_s * 0.8:
        return ProbeResult(
            technique="time", vulnerable=True, confidence="medium",
            severity="high",
            signal=(f"response delay {inj_s:.1f}s vs baseline {base_s:.1f}s "
                    f"(threshold {threshold_s:.0f}s)"),
            payload=payload,
            baseline_response_snippet=baseline.body[:300],
            injected_response_snippet=injected.body[:300],
            response_delta={"baseline_ms": round(baseline.elapsed_ms, 1),
                            "injected_ms": round(injected.elapsed_ms, 1),
                            "threshold_s": threshold_s},
        )
    return None


def analyze_union(baseline: ResponseData, injected: ResponseData,
                  payload: str) -> Optional[ProbeResult]:
    for marker in UNION_MARKERS:
        if marker in injected.body and marker not in baseline.body:
            return ProbeResult(
                technique="union", vulnerable=True, confidence="high",
                severity="high",
                signal=f"UNION marker {marker!r} reflected in response "
                       f"(detection marker only, no data extracted)",
                payload=payload,
                baseline_response_snippet=baseline.body[:300],
                injected_response_snippet=injected.body[max(0, injected.body.find(marker) - 120): injected.body.find(marker) + 160],
                response_delta={"marker": marker, "status": injected.status},
            )
    return None


# ------------------------------------------------------------------ parameter scanner
class ParameterScanner:
    """Runs all enabled techniques against one parameter."""

    def __init__(self, cfg: ScanConfig, send_fn: Callable[..., ResponseData]):
        self.cfg = cfg
        self.send = send_fn  # (url, headers, cookies, body) -> ResponseData

    def scan(self, param: Parameter,
             build_request: Callable,
             preview: Callable,
             progress: Optional[Callable[[int], None]] = None,
             cancelled: Optional[Callable[[], bool]] = None) -> List[ProbeResult]:
        from app.core.http_client import build_request as _br
        results: List[ProbeResult] = []
        techniques = set(self.cfg.techniques)

        # Baseline
        url, headers, cookies, body = _br(self.cfg, param, param.value)
        baseline = self.send(url, headers, cookies, body)

        def emit(payload: str, res: ProbeResult) -> ProbeResult:
            res.payload = payload
            res.baseline_request = preview(self.cfg.method, url, headers, cookies, body)
            res.baseline_response_snippet = res.baseline_response_snippet or baseline.body[:400]
            results.append(res)
            return res

        # ---- error-based
        if "error" in techniques:
            for payload in ERROR_PAYLOADS:
                if cancelled and cancelled():
                    break
                assert_safe(payload)
                iu, ih, ic, ib = _br(self.cfg, param, payload)
                resp = self.send(iu, ih, ic, ib)
                r = analyze_error(baseline, resp)
                if r:
                    emit(payload, r)
                    break
                if progress:
                    progress(1)
                time.sleep(0.01)

        # ---- boolean-based blind
        if "boolean" in techniques:
            for ptrue, pfalse in BOOLEAN_PAIRS:
                if cancelled and cancelled():
                    break
                assert_safe(ptrue)
                assert_safe(pfalse)
                tu, th, tc, tb = _br(self.cfg, param, ptrue)
                fu, fh, fc, fb = _br(self.cfg, param, pfalse)
                t_resp = self.send(tu, th, tc, tb)
                f_resp = self.send(fu, fh, fc, fb)
                r = analyze_boolean(baseline, t_resp, f_resp, ptrue, pfalse)
                if r:
                    emit(ptrue, r)
                    break
                if progress:
                    progress(2)
                time.sleep(0.01)

        # ---- time-based blind (opt-in; capped payloads)
        if "time" in techniques and not self.cfg.safe_mode:
            delay = min(int(self.cfg.time_threshold_s) or 5, 5)
            for tpl in TIME_PAYLOADS:
                if cancelled and cancelled():
                    break
                payload = tpl.format(d=delay)
                assert_safe(payload)
                iu, ih, ic, ib = _br(self.cfg, param, payload)
                resp = self.send(iu, ih, ic, ib)
                r = analyze_time(baseline, resp, payload, self.cfg.time_threshold_s)
                if r:
                    emit(payload, r)
                    break
                if progress:
                    progress(1)

        # ---- union-based (markers only)
        if "union" in techniques and not self.cfg.safe_mode:
            for tpl in UNION_PAYLOADS:
                if cancelled and cancelled():
                    break
                payload = tpl.format(marker=UNION_MARKERS[0])
                assert_safe(payload)
                iu, ih, ic, ib = _br(self.cfg, param, payload)
                resp = self.send(iu, ih, ic, ib)
                r = analyze_union(baseline, resp, payload)
                if r:
                    emit(payload, r)
                    break
                if progress:
                    progress(1)

        return results
