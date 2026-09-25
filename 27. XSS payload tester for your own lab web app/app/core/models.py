"""Core domain models for XPT (XSS Payload Tester)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

PARAMETER_LOCATIONS = ["query", "body", "header", "cookie"]
XSS_TYPES = ["reflected", "stored", "dom"]
CONTEXTS = ["html_body", "html_attribute", "js_string", "url_param", "css_context", "unknown"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCE_LEVELS = ["high", "medium", "low"]


@dataclass
class Parameter:
    """A single injectable parameter."""

    location: str
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
    """Everything needed to run an XSS detection scan."""

    target_url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_type: str = "none"
    parameters: List[Parameter] = field(default_factory=list)
    contexts: List[str] = field(default_factory=lambda: list(CONTEXTS[:-1]))
    custom_payloads: List[str] = field(default_factory=list)
    delay_ms: int = 40
    timeout: float = 10.0
    max_requests: int = 600
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
            "contexts": self.contexts, "custom_payloads": self.custom_payloads,
            "delay_ms": self.delay_ms, "timeout": self.timeout,
            "max_requests": self.max_requests,
            "follow_redirects": self.follow_redirects,
            "verify_ssl": self.verify_ssl, "proxy": self.proxy,
        }


@dataclass
class XssFinding:
    """A flagged XSS finding with reflection/execution evidence."""

    url: str
    method: str
    parameter_name: str
    parameter_location: str
    xss_type: str                    # 'reflected', 'stored', 'dom'
    context: str                     # 'html_body', 'html_attribute', ...
    payload: str = ""
    encoded_in_response: bool = False
    encoding_applied: str = ""       # 'html_encoded', 'url_encoded', 'none'
    browser_confirmed: bool = False
    confirmation_method: str = ""    # 'alert', 'dom_mutation', 'console', 'reflection'
    severity: str = "high"
    confidence: str = "medium"
    csp_present: bool = False
    signal: str = ""
    reflection_snippet: str = ""
    request: str = ""
    response_snippet: str = ""
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
            "xss_type": self.xss_type, "context": self.context,
            "payload": self.payload,
            "encoded_in_response": self.encoded_in_response,
            "encoding_applied": self.encoding_applied,
            "browser_confirmed": self.browser_confirmed,
            "confirmation_method": self.confirmation_method,
            "severity": self.severity, "confidence": self.confidence,
            "csp_present": self.csp_present, "signal": self.signal,
            "reflection_snippet": self.reflection_snippet,
            "request": self.request, "response_snippet": self.response_snippet,
            "remediation": self.remediation, "references": self.references,
            "status": self.status, "resp_time_ms": self.resp_time_ms,
        }

    def summary(self) -> str:
        confirmed = "browser-confirmed" if self.browser_confirmed else "reflection"
        return (f"[{self.severity.upper()}] {self.xss_type} XSS @ "
                f"{self.parameter_location}:{self.parameter_name} "
                f"({self.context}, {confirmed})")


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)
