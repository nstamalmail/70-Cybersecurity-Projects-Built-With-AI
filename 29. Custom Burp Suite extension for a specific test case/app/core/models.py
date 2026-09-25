"""Core data models for CBSEF (architecture.md §3.4 CandidateFinding)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

TEST_CASES = ["mass_assignment", "jwt_confusion", "oauth_redirect", "introspection"]
STATUSES = ["candidate", "confirmed", "false_positive"]
CONFIDENCE_LEVELS = ["high", "medium", "low"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class CandidateFinding:
    finding_id: str
    test_case: str                     # 'mass_assignment', 'jwt_confusion', ...
    timestamp: float = field(default_factory=time.time)
    url: str = ""
    method: str = ""
    endpoint: str = ""
    parameter: str = ""                # '' when n/a
    confidence: str = "medium"         # high / medium / low
    status: str = "candidate"          # candidate / confirmed / false_positive
    signal_description: str = ""
    baseline_request: str = ""
    baseline_response: str = ""
    probe_request: str = ""
    probe_response: str = ""
    differential: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    id: Optional[int] = None
    session_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "session_id": self.session_id,
            "finding_id": self.finding_id, "test_case": self.test_case,
            "timestamp": self.timestamp, "url": self.url, "method": self.method,
            "endpoint": self.endpoint, "parameter": self.parameter,
            "confidence": self.confidence, "status": self.status,
            "signal_description": self.signal_description,
            "baseline_request": self.baseline_request,
            "baseline_response": self.baseline_response,
            "probe_request": self.probe_request,
            "probe_response": self.probe_response,
            "differential": self.differential,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        return (f"[{self.status}] {self.test_case} @ {self.method} "
                f"{self.endpoint} ({self.confidence})")


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def new_finding_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)
