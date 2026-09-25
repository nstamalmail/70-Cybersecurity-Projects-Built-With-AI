"""Notifier tests (stdlib-only, no network required for the bulk of them).

Run:  python tests/test_notifiers.py
"""
from __future__ import annotations

import json
import os
import queue
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.events import Alert
from siem.notifiers import (  # noqa: E402
    EchoNotifier,
    NotificationError,
    WebhookNotifier,
    build_notifier,
    build_notifiers,
    _envelope,
    _render_template,
)


def _alert(**overrides) -> Alert:
    base = {
        "ts": time.time(),
        "rule_id": "rule_x",
        "rule_name": "Test Rule",
        "severity": "high",
        "summary": "test alert summary",
        "group_key": "host-1",
        "count": 3,
        "status": "open",
        "fields": {"host": "host-1", "src_ip": "10.0.0.1", "status": "404"},
    }
    base.update(overrides)
    return Alert(**base)


def test_envelope() -> bool:
    a = _alert()
    env = _envelope(a)
    ok = env["rule_id"] == "rule_x"
    ok = ok and env["severity"] == "high"
    ok = ok and env["summary"] == "test alert summary"
    ok = ok and env["event_sample"] == "host=host-1, src_ip=10.0.0.1"
    ok = ok and env["count"] == 3
    ok = ok and env["id"] is None
    ok = ok and env["status"] == "open"
    print(f"[{'PASS' if ok else 'FAIL'}] notifier envelope shape")
    return ok


def test_render_default_body() -> bool:
    a = _alert(summary="something happened")
    body = _render_template("default", a, body=True)
    ok = "Test Rule (rule_x)" in body
    ok = ok and "high" in body.lower()
    ok = ok and "something happened" in body
    ok = ok and "host=host-1" in body
    ok = ok and "Count     : 3" in body
    ok = ok and "Event     : host=host-1, src_ip=10.0.0.1" in body
    print(f"[{'PASS' if ok else 'FAIL'}] default body template renders alert fields")
    return ok


def test_render_default_subject() -> bool:
    a = _alert()
    subj = _render_template("default", a, body=False)
    ok = "Test Rule" in subj and "HIGH" in subj
    print(f"[{'PASS' if ok else 'FAIL'}] default subject template renders a one-liner")
    return ok


def test_render_unknown_template() -> bool:
    a = _alert()
    try:
        _render_template("nope", a, body=False)
    except ValueError as exc:
        ok = "unknown template" in str(exc)
        print(f"[{'PASS' if ok else 'FAIL'}] unknown template raises ValueError")
        return ok
    print("[FAIL] unknown template did not raise")
    return False


def test_build_notifier_webhook() -> bool:
    cfg = {
        "type": "webhook",
        "url": "https://example.invalid/hook",
        "method": "POST",
        "timeout": 7,
        "headers": {"Authorization": "Bearer t", "X-Debug": "1"},
        "body_template": "default",
    }
    n = build_notifier(cfg)
    ok = isinstance(n, WebhookNotifier)
    ok = ok and n.url == "https://example.invalid/hook"
    ok = ok and n.method == "POST"
    ok = ok and n.timeout == 7
    ok = ok and n.headers.get("Authorization") == "Bearer t"
    ok = ok and n.headers.get("X-Debug") == "1"
    ok = ok and n.body_template == "default"
    # Content-Type is injected at send time, not stored in config headers.
    print(f"[{'PASS' if ok else 'FAIL'}] build webhook notifier from config")
    return ok


def test_build_notifier_bad_type() -> bool:
    try:
        build_notifier({"type": "bogus"})
    except ValueError as exc:
        ok = "unknown notifier type" in str(exc) and "bogus" in str(exc)
        print(f"[{'PASS' if ok else 'FAIL'}] unknown notifier type raises ValueError")
        return ok
    print("[FAIL] unknown notifier type did not raise")
    return False


def test_build_notifier_missing_url() -> bool:
    try:
        build_notifier({"type": "webhook"})
    except ValueError as exc:
        ok = "url" in str(exc).lower()
        print(f"[{'PASS' if ok else 'FAIL'}] webhook without url raises ValueError")
        return ok
    print("[FAIL] webhook without url did not raise")
    return False


def test_build_notifiers_from_config() -> bool:
    cfg = {
        "notifiers": [
            {"type": "echo"},
            {"type": "webhook", "url": "https://example.invalid/hook"},
            {"type": "webhook"},  # missing url -> skipped
            "not a dict",         # skipped
            {"type": "bogus"},    # skipped
        ]
    }
    out = build_notifiers(cfg)
    ok = len(out) == 2
    ok = ok and isinstance(out[0], EchoNotifier)
    ok = ok and isinstance(out[1], WebhookNotifier)
    print(f"[{'PASS' if ok else 'FAIL'}] build_notifiers keeps good entries, skips bad ones")
    return ok


def test_build_notifiers_no_key() -> bool:
    out = build_notifiers({})
    ok = out == []
    print(f"[{'PASS' if ok else 'FAIL'}] empty config yields no notifiers")
    return ok


def test_notifier_no_raise_on_notify() -> bool:
    """NotificationError from a notifier is an expected failure mode; confirm the
    exception is the public type."""
    n = WebhookNotifier({"url": "https://example.invalid/hook"})
    try:
        n.notify(_alert())
    except NotificationError:
        print("[PASS] webhook notify raises NotificationError on unreachable host")
        return True
    except Exception as exc:
        print(f"[FAIL] webhook notify raised unexpected type: {type(exc).__name__}: {exc}")
        return False
    print("[FAIL] webhook notify did not raise on an unreachable host")
    return False


def test_echo_notifier_delivers() -> bool:
    held: list[str] = []
    old = sys.stdout

    class Holder:
        def write(self, s: str) -> int:
            if s.strip():
                held.append(s.rstrip("\n"))
            return len(s)

        def flush(self) -> None:
            pass

    sys.stdout = Holder()
    try:
        n = EchoNotifier({})
        n.notify(_alert(rule_id="r1", summary="boom"))
    finally:
        sys.stdout = old
    ok = len(held) == 1
    ok = ok and held[0].startswith("[NOTIFIER:echo]")
    ok = ok and '"rule_id": "r1"' in held[0]
    ok = ok and '"summary": "boom"' in held[0]
    print(f"[{'PASS' if ok else 'FAIL'}] echo notifier prints a JSON envelope to stdout")
    return ok


def test_echo_notifier_failure_swallowed_by_caller() -> bool:
    """EchoNotifier is not expected to fail, but we model the contract: the
    pipeline catches exceptions from ``notify``."""
    held: list[BaseException] = []
    try:
        n = EchoNotifier({})
        try:
            n.notify(_alert())
        except Exception as exc:
            held.append(exc)
    except Exception:
        pass
    ok = len(held) == 0
    print(f"[{'PASS' if ok else 'FAIL'}] echo notifier did not raise on a normal alert")
    return ok


def test_notifier_kind_attributes() -> bool:
    ok = EchoNotifier.kind == "echo"
    ok = ok and WebhookNotifier.kind == "webhook"
    print(f"[{'PASS' if ok else 'FAIL'}] notifier kinds expose a stable `kind` attr")
    return ok


def main() -> int:
    checks = [
        test_envelope,
        test_render_default_body,
        test_render_default_subject,
        test_render_unknown_template,
        test_build_notifier_webhook,
        test_build_notifier_bad_type,
        test_build_notifier_missing_url,
        test_build_notifiers_from_config,
        test_build_notifiers_no_key,
        test_notifier_no_raise_on_notify,
        test_echo_notifier_delivers,
        test_echo_notifier_failure_swallowed_by_caller,
        test_notifier_kind_attributes,
    ]
    ok = True
    for check in checks:
        try:
            ok = check() and ok
        except Exception as exc:  # pragma: no cover
            ok = False
            print(f"[FAIL] {check.__name__} raised: {exc!r}")
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
