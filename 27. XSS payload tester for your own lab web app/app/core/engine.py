"""Scan engine worker thread for XPT.

Workflow per architecture.md §5: inject payloads -> analyze reflection ->
classify encoding/context -> (optional) browser confirmation is left to the
user via the embedded preview; engine emits reflection findings with
execution-risk assessment. Browser automation (Playwright) is optional and
detected at runtime.
"""

from __future__ import annotations

import queue
import threading

import requests

from app.core import payloads as pl
from app.core.http_client import HttpClient, build_request, discover_parameters, request_preview
from app.core.models import ScanConfig, XssFinding, now_iso
from app.core.reflection import analyze_reflection, execution_risk
from app.core.remediation import build_remediation
from app.core.http_client import parse_headers_text


def has_playwright() -> bool:
    import importlib.util
    return importlib.util.find_spec("playwright") is not None


class ScanEngine(threading.Thread):
    def __init__(self, cfg: ScanConfig, events: "queue.Queue"):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.events = events
        self.stats = {"requests": 0, "errors": 0, "findings": 0, "parameters": 0,
                      "payloads": 0}
        self.running = True
        self._cancel = threading.Event()

    def stop(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def mark_done(self) -> None:
        self.running = False

    def _emit(self, ev_type: str, **kw) -> None:
        self.events.put({"type": ev_type, **kw})

    def _log(self, msg: str) -> None:
        self._emit("log", message=msg)

    def _send(self, url, headers, cookies, body):
        try:
            resp = self._client.send(self.cfg.method, url, headers, cookies, body)
            self.stats["requests"] += 1
            return resp
        except requests.RequestException as exc:
            self.stats["errors"] += 1
            self._log(f"HTTP error: {exc.__class__.__name__}: {exc}")
            return None

    def run(self) -> None:
        self._emit("status", message="Starting…")
        self._client = HttpClient(self.cfg)
        self._log(f"Target: {self.cfg.method} {self.cfg.target_url}")
        if not has_playwright():
            self._log("Playwright not installed — findings are reflection-based "
                      "(install playwright for browser confirmation).")

        params = [p for p in self.cfg.parameters if p.enabled]
        self.stats["parameters"] = len(params)
        if not params:
            self._emit("status", message="Finished (no enabled parameters)")
            self._log("No enabled parameters to test.")
            self._emit("scan_finished")
            return

        # Baseline + CSP check
        base_url, base_h, base_c, base_b = build_request(
            self.cfg, params[0], params[0].value)
        base_resp = self._send(base_url, base_h, base_c, base_b)
        csp_present = bool(base_resp is not None and (
            "content-security-policy" in {k.lower() for k in base_resp.headers}))

        payload_list = pl.all_payloads(self.cfg.contexts, self.cfg.custom_payloads)
        self.stats["payloads"] = len(payload_list)
        self._log(f"Testing {len(params)} parameter(s) with {len(payload_list)} "
                  f"payload(s); CSP {'present' if csp_present else 'not observed'}.")

        seen_keys = set()
        done = 0
        for param in params:
            if self.cancelled():
                break
            self._emit("status", message=f"Testing {param.location}:{param.name}")
            for payload in payload_list:
                if self.cancelled() or self.stats["requests"] >= self.cfg.max_requests:
                    break
                url, headers, cookies, body = build_request(self.cfg, param, payload)
                resp = self._send(url, headers, cookies, body)
                if resp is None:
                    continue
                text = resp.text
                refl = analyze_reflection(payload, text)
                if not refl.reflected:
                    continue
                risk = execution_risk(refl, payload)
                encoded = refl.encoding_applied not in ("none",)
                if not risk and encoded:
                    continue  # safe reflection — not a finding
                if not risk:
                    continue  # harmless reflection (no executable signature)

                key = (param.key(), refl.context, payload[:60])
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                xss_type = "reflected"
                sev = "high" if risk else "low"
                conf = "high" if risk and refl.encoding_applied == "none" else "medium"
                finding = XssFinding(
                    url=url, method=self.cfg.method,
                    parameter_name=param.name, parameter_location=param.location,
                    xss_type=xss_type, context=refl.context, payload=payload,
                    encoded_in_response=encoded,
                    encoding_applied=refl.encoding_applied,
                    browser_confirmed=False,
                    confirmation_method="reflection",
                    severity=sev, confidence=conf,
                    csp_present=csp_present,
                    signal=("raw reflection with executable context"
                            if risk else "payload reflected with partial encoding"),
                    reflection_snippet=refl.snippet[:800],
                    request=request_preview(self.cfg.method, url, headers, cookies, body),
                    response_snippet=text[:600],
                    remediation=build_remediation(refl.context, xss_type, csp_present),
                    references=["OWASP XSS Prevention Cheat Sheet", "CWE-79"],
                    status=resp.status_code,
                    resp_time_ms=resp.elapsed.total_seconds() * 1000.0,
                )
                self._emit("finding", finding=finding)
                self.stats["findings"] += 1
                self._log(f"⚠ {finding.summary()}")
            done += 1
            self._emit("progress", done=done, total=len(params))

        self._emit("status", message="Stopped" if self.cancelled() else "Finished")
        self._log(f"Scan complete: {self.stats['requests']} requests, "
                  f"{self.stats['findings']} findings, {self.stats['errors']} errors")
        self._emit("scan_finished")
