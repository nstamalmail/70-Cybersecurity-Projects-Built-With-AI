"""Core domain models for the fuzzer."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Injection point kinds supported by the injector.
INJECTION_KINDS = [
    "query",
    "path",
    "header",
    "cookie",
    "body_form",
    "body_json",
    "body_raw",
]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Supported payload categories (keys also used by the database / reports).
PAYLOAD_CATEGORIES = [
    "xss",
    "sqli",
    "cmdi",
    "path_traversal",
    "ssti",
    "open_redirect",
    "crlf",
    "ldap",
    "nosql",
    "custom",
]


@dataclass
class InjectionPoint:
    """A single user-controlled injection point."""

    kind: str
    name: str
    value: str
    enabled: bool = True

    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "value": self.value, "enabled": self.enabled}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "InjectionPoint":
        return cls(kind=d["kind"], name=d["name"], value=d.get("value", ""), enabled=d.get("enabled", True))


@dataclass
class RequestSpec:
    """A concrete HTTP request envelope."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_type: str = "none"  # none | form | json | raw
    timeout: float = 10.0
    allow_redirects: bool = True
    verify: bool = True
    proxies: Optional[Dict[str, str]] = None

    def preview(self) -> str:
        """Human-readable raw HTTP request preview."""
        lines = [f"{self.method} {self.url}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        for k, v in self.cookies.items():
            lines.append(f"Cookie: {k}={v}")
        lines.append("")
        if self.body:
            lines.append(self.body)
        return "\n".join(lines)


@dataclass
class ScanConfig:
    """Everything needed to run a scan."""

    target_url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_type: str = "none"
    injection_points: List[InjectionPoint] = field(default_factory=list)
    categories: List[str] = field(default_factory=lambda: list(PAYLOAD_CATEGORIES[:-1]))
    encodings: List[str] = field(default_factory=lambda: ["none", "url"])
    custom_payloads: List[str] = field(default_factory=list)
    threads: int = 6
    delay_ms: int = 50
    timeout: float = 10.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxy: str = ""
    max_requests: int = 1500
    time_based: bool = True
    authorized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "method": self.method,
            "headers": self.headers,
            "cookies": self.cookies,
            "body": self.body,
            "body_type": self.body_type,
            "injection_points": [ip.to_dict() for ip in self.injection_points],
            "categories": self.categories,
            "encodings": self.encodings,
            "custom_payloads": self.custom_payloads,
            "threads": self.threads,
            "delay_ms": self.delay_ms,
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "verify_ssl": self.verify_ssl,
            "proxy": self.proxy,
            "max_requests": self.max_requests,
            "time_based": self.time_based,
        }


@dataclass
class Finding:
    """A validated security finding."""

    category: str
    technique: str
    severity: str
    injection_kind: str
    injection_name: str
    payload: str
    encoding: str
    url: str
    status: int
    resp_len: int
    resp_time_ms: float
    evidence: str
    request: str = ""
    response: str = ""
    ts: float = field(default_factory=time.time)
    id: Optional[int] = None
    scan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ts": self.ts,
            "category": self.category,
            "technique": self.technique,
            "severity": self.severity,
            "injection_kind": self.injection_kind,
            "injection_name": self.injection_name,
            "payload": self.payload,
            "encoding": self.encoding,
            "url": self.url,
            "status": self.status,
            "resp_len": self.resp_len,
            "resp_time_ms": self.resp_time_ms,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
        }

    def summary(self) -> str:
        return f"[{self.severity.upper()}] {self.category}/{self.technique} @ {self.injection_kind}:{self.injection_name} ({self.encoding})"


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)