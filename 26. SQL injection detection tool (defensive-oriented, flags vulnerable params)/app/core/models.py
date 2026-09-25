"""Core domain models for SIDT (SQL Injection Detection Tool)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Parameter locations supported by the injector.
PARAMETER_LOCATIONS = ["query", "body", "header", "cookie"]

# Detection techniques (safe mode = error + boolean only).
TECHNIQUES = ["error", "boolean", "time", "union"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCE_LEVELS = ["high", "medium", "low"]


@dataclass
class Parameter:
    """A single testable parameter discovered or entered manually."""

    location: str          # 'query', 'body', 'header', 'cookie'
    name: str
    value: str
    enabled: bool = True

    def key(self) -> str:
        return f"{self.location}:{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {"location": self.location, "name": self.name,
                "value": self.value, "enabled": self.enabled}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Parameter":
        return cls(location=d.get("location", "query"), name=d.get("name", ""),
                   value=d.get("value", ""), enabled=bool(d.get("enabled", True)))


@dataclass
class ScanConfig:
    """Everything needed to run a SQLi detection scan."""

    target_url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_type: str = "none"          # none | form | json | raw
    parameters: List[Parameter] = field(default_factory=list)
    techniques: List[str] = field(default_factory=lambda: ["error", "boolean"])
    safe_mode: bool = True
    threads: int = 4
    delay_ms: int = 40
    timeout: float = 10.0
    time_threshold_s: float = 5.0    # time-based delta threshold
    max_requests: int = 800
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxy: str = ""
    authorized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url, "method": self.method,
            "headers": self.headers, "cookies": self.cookies,
            "body": self.body, "body_type": self.body_type,
            "parameters": [p.to_dict() for p in self.parameters],
            "techniques": self.techniques, "safe_mode": self.safe_mode,
            "threads": self.threads, "delay_ms": self.delay_ms,
            "timeout": self.timeout, "time_threshold_s": self.time_threshold_s,
            "max_requests": self.max_requests,
            "follow_redirects": self.follow_redirects,
            "verify_ssl": self.verify_ssl, "proxy": self.proxy,
        }


@dataclass
class SqlInjectionFinding:
    """A flagged parameter with evidence and remediation."""

    url: str
    method: str
    parameter_name: str
    parameter_location: str          # 'query', 'body', 'header', 'cookie'
    technique: str                   # 'error', 'boolean', 'time', 'union'
    confidence: str                  # 'high', 'medium', 'low'
    severity: str                    # 'critical', 'high', 'medium', 'low'
    dbms_hint: str = ""              # 'mysql', 'postgresql', 'mssql', ...
    signal: str = ""                 # human-readable signal description
    payload: str = ""
    baseline_request: str = ""
    injected_request: str = ""
    baseline_response_snippet: str = ""
    injected_response_snippet: str = ""
    response_delta: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    status: int = 0
    resp_time_ms: float = 0.0
    id: Optional[int] = None
    scan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "scan_id": self.scan_id,
            "url": self.url, "method": self.method,
            "parameter_name": self.parameter_name,
            "parameter_location": self.parameter_location,
            "technique": self.technique, "confidence": self.confidence,
            "severity": self.severity, "dbms_hint": self.dbms_hint,
            "signal": self.signal, "payload": self.payload,
            "baseline_request": self.baseline_request,
            "injected_request": self.injected_request,
            "baseline_response_snippet": self.baseline_response_snippet,
            "injected_response_snippet": self.injected_response_snippet,
            "response_delta": self.response_delta,
            "remediation": self.remediation, "references": self.references,
            "status": self.status, "resp_time_ms": self.resp_time_ms,
        }

    def summary(self) -> str:
        return (f"[{self.severity.upper()}] {self.parameter_location}:"
                f"{self.parameter_name} — {self.technique}-based "
                f"({self.confidence} confidence)")


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)
