"""Correlation rules and the in-memory matching engine.

Rule types:
  * regex     — single event matches a pattern → alert.
  * threshold — >= N matching events for the same group key within a window → alert.
  * sequence  — ordered steps (finite automaton) within a window → alert.

Dedup: an alert for the same (rule, group_key) within ``cooldown`` seconds is
suppressed.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Callable, Optional

from .events import Alert, NormalizedEvent

RULE_TYPES = ("regex", "threshold", "sequence")
SEVERITIES = ("low", "medium", "high", "critical")

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "rule_brute_force",
        "name": "Possible Brute Force",
        "description": "Multiple failed login/authentication attempts from the same host in a short window.",
        "rule_type": "threshold", "severity": "high", "enabled": True,
        "pattern": r"(?i)(failed|invalid|denied).*(password|login|auth)",
        "field": "message", "threshold": 5, "window": 60,
        "group_by": "host", "cooldown": 60,
    },
    {
        "id": "rule_sqli",
        "name": "SQL Injection Attempt",
        "description": "Classic SQL injection payloads in log messages.",
        "rule_type": "regex", "severity": "critical", "enabled": True,
        "pattern": r"(?i)(union\s+(all\s+)?select|select\s+.*\s+from\s+|'\s*or\s*'1'\s*=\s*'1|--\s*$|;\s*drop\s+table)",
        "field": "message",
    },
    {
        "id": "rule_many_404",
        "name": "Web Scanning / Many 404s",
        "description": "Large number of HTTP 404 responses within a window (directory brute force).",
        "rule_type": "threshold", "severity": "medium", "enabled": True,
        "pattern": r"\s404\s", "field": "message",
        "threshold": 20, "window": 60, "group_by": "src_ip", "cooldown": 300,
    },
    {
        "id": "rule_priv_esc",
        "name": "Privilege Escalation / sudo Failure",
        "description": "Failed privilege escalation attempts (sudo/su denial).",
        "rule_type": "regex", "severity": "high", "enabled": True,
        "pattern": r"(?i)\b(sudo|su)\b.*(not in sudoers|incorrect password|authentication failure|operation not permitted|denied)",
        "field": "message",
    },
    {
        "id": "rule_seq_fail_success",
        "name": "Fail-then-Success Login",
        "description": "A failed login followed by a successful login from the same host — possible compromise.",
        "rule_type": "sequence", "severity": "high", "enabled": True,
        "window": 120, "group_by": "host", "cooldown": 300,
        "steps": [
            {"label": "failed", "pattern": r"(?i)(failed|invalid).*(password|login|auth)"},
            {"label": "success", "pattern": r"(?i)(accepted|successful|session opened).*(password|login|auth)"},
        ],
    },
    {
        "id": "rule_error_spike",
        "name": "Error Spike",
        "description": "Unusual number of error/critical/fatal messages in a short window.",
        "rule_type": "threshold", "severity": "medium", "enabled": True,
        "pattern": r"(?i)\b(error|critical|fatal)\b", "field": "message",
        "threshold": 10, "window": 60, "group_by": None, "cooldown": 120,
    },
    {
        "id": "rule_win_failed_logon",
        "name": "Windows Failed Logon (4625)",
        "description": "Windows Security event 4625 - an account failed to log on (works with the winevt source).",
        "rule_type": "regex", "severity": "high", "enabled": True,
        "pattern": r"EventID=4625", "field": "message",
    },
]


def _coerce(value: Any, default: Any, cast: Callable[[Any], Any]) -> Any:
    try:
        return cast(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Rule:
    id: str
    name: str
    description: str
    rule_type: str
    severity: str
    enabled: bool = True
    pattern: str = ""
    field: str = "message"
    threshold: int = 5
    window: float = 60.0
    group_by: str = ""
    cooldown: float = 60.0
    steps: list[dict[str, str]] = dataclass_field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        steps = d.get("steps") or []
        if isinstance(steps, str):
            steps = json.loads(steps) if steps.strip() else []
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name", "")),
            description=str(d.get("description", "")),
            rule_type=str(d.get("rule_type", "regex")),
            severity=str(d.get("severity", "medium")).lower(),
            enabled=bool(d.get("enabled", True)),
            pattern=str(d.get("pattern", "")),
            field=str(d.get("field", "message")),
            threshold=_coerce(d.get("threshold"), 5, int),
            window=float(_coerce(d.get("window"), 60, float)),
            group_by=str(d.get("group_by", "")),
            cooldown=float(_coerce(d.get("cooldown"), 60, float)),
            steps=steps if isinstance(steps, list) else [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "rule_type": self.rule_type, "severity": self.severity,
            "enabled": self.enabled, "pattern": self.pattern, "field": self.field,
            "threshold": self.threshold, "window": self.window,
            "group_by": self.group_by, "cooldown": self.cooldown,
            "steps": self.steps,
        }

    # -- matching helpers ---------------------------------------------------
    def _field_value(self, ev: NormalizedEvent) -> str:
        f = self.field
        if f in ("", "message"):
            return ev.message
        if f == "host":
            return ev.host or ""
        if f == "source":
            return ev.source or ""
        v = ev.fields.get(f)
        if v is None:
            return ""
        return v if isinstance(v, str) else json.dumps(v)

    def _step_matches(self, pattern: str, ev: NormalizedEvent) -> bool:
        if not pattern:
            return False
        try:
            return _search(pattern, self._field_value(ev)) is not None
        except re.error:
            return False

    def build_summary(self, ev: NormalizedEvent, count: int = 1) -> str:
        key = self.group_key_of(ev)
        if self.rule_type == "threshold":
            return f"{count}x in {int(self.window)}s from {key}"
        if self.rule_type == "sequence":
            return f"{len(self.steps)}-step sequence completed from {key}"
        snippet = ev.message.strip()[:100]
        return f"match on {ev.host or ev.source}: {snippet}"

    def group_key_of(self, ev: NormalizedEvent) -> str:
        g = self.group_by
        if not g:
            return "global"
        if g == "host":
            return ev.host or "?"
        if g == "src_ip":
            v = ev.fields.get("src_ip")
            return str(v) if v else "?"
        v = ev.fields.get(g)
        return str(v) if v else (ev.host or "?")


import re

_re_cache: dict[str, "re.Pattern[str]"] = {}


def _search(pattern: str, text: str) -> Optional[re.Match]:
    """Small LRU-ish cache so hot rules do not recompile regexes."""
    compiled = _re_cache.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern)
        if len(_re_cache) > 512:
            _re_cache.clear()
        _re_cache[pattern] = compiled
    return compiled.search(text)


def safe_compile(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Evaluates all enabled rules against each normalized event."""

    def __init__(self, rules: list[Rule], alert_cb: Callable[[Alert], None]) -> None:
        self.alert_cb = alert_cb
        self.rules: list[Rule] = []
        self._threshold_state: dict[str, dict[str, deque]] = {}
        self._seq_state: dict[str, dict[str, list]] = {}  # rule_id -> key -> [step, last_ts]
        self._last_alert: dict[tuple[str, str], float] = {}
        self.reload_rules(rules)

    def reload_rules(self, rules: list[Rule]) -> None:
        self.rules = [r for r in rules if r.enabled]
        self._threshold_state.clear()
        self._seq_state.clear()
        self._last_alert.clear()

    # -- main entry ---------------------------------------------------------
    def process(self, ev: NormalizedEvent) -> None:
        for rule in self.rules:
            try:
                self._check_rule(rule, ev)
            except Exception:
                continue  # a broken rule must never kill the pipeline

    # -- dispatch -----------------------------------------------------------
    def _check_rule(self, rule: Rule, ev: NormalizedEvent) -> None:
        if rule.rule_type == "regex":
            if rule.pattern and rule._step_matches(rule.pattern, ev):
                self._fire(rule, ev, ev.host or "global", 1)
        elif rule.rule_type == "threshold":
            self._check_threshold(rule, ev)
        elif rule.rule_type == "sequence":
            self._check_sequence(rule, ev)

    def _check_threshold(self, rule: Rule, ev: NormalizedEvent) -> None:
        if not rule.pattern or not rule._step_matches(rule.pattern, ev):
            return
        key = rule.group_key_of(ev)
        dq = self._threshold_state.setdefault(rule.id, {}).get(key)
        if dq is None:
            dq = self._threshold_state[rule.id][key] = deque()
        dq.append(ev.ts)
        cutoff = ev.ts - rule.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= max(1, rule.threshold):
            count = len(dq)
            dq.clear()  # reset so the same burst does not refire immediately
            self._fire(rule, ev, key, count)

    def _check_sequence(self, rule: Rule, ev: NormalizedEvent) -> None:
        if not rule.steps:
            return
        key = rule.group_key_of(ev)
        state = self._seq_state.setdefault(rule.id, {}).get(key)
        if state is None:
            if rule._step_matches(rule.steps[0].get("pattern", ""), ev):
                self._seq_state[rule.id][key] = [0, ev.ts]
            return
        step_idx, last_ts = state
        if ev.ts - last_ts > rule.window:
            # window expired — restart if this event begins a new attempt
            if rule._step_matches(rule.steps[0].get("pattern", ""), ev):
                self._seq_state[rule.id][key] = [0, ev.ts]
            else:
                del self._seq_state[rule.id][key]
            return
        if rule._step_matches(rule.steps[0].get("pattern", ""), ev):
            self._seq_state[rule.id][key] = [0, ev.ts]  # restart attempt
            return
        nxt = step_idx + 1
        if nxt < len(rule.steps) and rule._step_matches(rule.steps[nxt].get("pattern", ""), ev):
            if nxt == len(rule.steps) - 1:
                del self._seq_state[rule.id][key]
                self._fire(rule, ev, key, len(rule.steps))
            else:
                self._seq_state[rule.id][key] = [nxt, ev.ts]

    # -- firing -------------------------------------------------------------
    def _fire(self, rule: Rule, ev: NormalizedEvent, key: str, count: int) -> None:
        dedup = (rule.id, key)
        last = self._last_alert.get(dedup)
        if last is not None and ev.ts - last < max(0.0, rule.cooldown):
            return
        self._last_alert[dedup] = ev.ts
        if len(self._last_alert) > 4096:
            now = time.time()
            self._last_alert = {k: v for k, v in self._last_alert.items() if now - v < 3600}
        summary = rule.build_summary(ev, count)
        alert = Alert(
            ts=ev.ts, rule_id=rule.id, rule_name=rule.name,
            severity=rule.severity, summary=summary, group_key=key,
            count=count, fields=dict(ev.fields),
        )
        self.alert_cb(alert)