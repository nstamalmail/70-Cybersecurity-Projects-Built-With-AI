"""Fuzz engine worker thread for SIDT.

Coordinates the scan lifecycle: baseline capture -> injection -> analysis ->
findings. Emits event dicts into a queue; the GUI main thread polls the queue.
Safe mode is enforced here regardless of GUI state.
"""

from __future__ import annotations

import queue
import threading
from typing import Optional

import requests

from app.core import techniques as tech
from app.core.http_client import HttpClient, build_request, request_preview
from app.core.models import ScanConfig, SqlInjectionFinding, now_iso
from app.core.remediation import build_remediation
from app.core.techniques import ParameterScanner, ResponseData, detect_waf


class ScanEngine(threading.Thread):
    def __init__(self, cfg: ScanConfig, events: "queue.Queue"):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.events = events
        self.stats = {"requests": 0, "errors": 0, "findings": 0, "parameters": 0}
        self.waf: str = ""
        self.running = True
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ control
    def stop(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def mark_done(self) -> None:
        self.running = False

    # ------------------------------------------------------------------ helpers
    def _emit(self, ev_type: str, **kw) -> None:
        self.events.put({"type": ev_type, **kw})

    def _log(self, msg: str) -> None:
        self._emit("log", message=msg)

    def _send(self, url, headers, cookies, body) -> ResponseData:
        client: HttpClient = self._client
        try:
            resp = client.send(self.cfg.method, url, headers, cookies, body)
            self.stats["requests"] += 1
            return ResponseData(
                status=resp.status_code,
                body=resp.text if isinstance(resp.text, str) else "",
                elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
                headers={k: v for k, v in resp.headers.items()},
            )
        except requests.RequestException as exc:
            self.stats["errors"] += 1
            self._log(f"HTTP error: {exc.__class__.__name__}: {exc}")
            return ResponseData(status=0, body="", elapsed_ms=0.0)

    # ------------------------------------------------------------------ WAF check
    def _check_waf(self) -> None:
        try:
            resp = self._client.send(self.cfg.method, self.cfg.target_url,
                                     self.cfg.headers, self.cfg.cookies, self.cfg.body)
            self.stats["requests"] += 1
            rd = ResponseData(resp.status_code, resp.text,
                              resp.elapsed.total_seconds() * 1000.0,
                              dict(resp.headers))
            self.waf = detect_waf(rd)
            if self.waf:
                self._log(f"WAF/edge detected: {self.waf} (defensive report only, no evasion)")
        except requests.RequestException:
            pass

    # ------------------------------------------------------------------ main
    def run(self) -> None:
        self._emit("status", message="Starting…")
        self._client = HttpClient(self.cfg)

        # 0) reachability + WAF fingerprint
        self._log(f"Target: {self.cfg.method} {self.cfg.target_url}")
        self._check_waf()

        # 1) baseline sanity
        params = [p for p in self.cfg.parameters if p.enabled]
        self.stats["parameters"] = len(params)
        if not params:
            self._emit("status", message="Finished (no enabled parameters)")
            self._log("No enabled parameters to test.")
            self._emit("scan_finished")
            return

        if self.cfg.safe_mode:
            self._log("Safe mode: error-based + boolean-based techniques only; "
                      "no time-delay or UNION payloads will be sent.")

        scanner = ParameterScanner(self.cfg, self._send)
        total = len(params)
        done = 0

        for param in params:
            if self.cancelled():
                break
            self._emit("status", message=f"Testing {param.location}:{param.name}")
            try:
                probes = scanner.scan(
                    param, build_request, request_preview,
                    cancelled=self.cancelled,
                )
            except Exception as exc:  # noqa: BLE001
                self.stats["errors"] += 1
                self._log(f"parameter {param.key()} failed: {exc}")
                probes = []

            for r in probes:
                finding = SqlInjectionFinding(
                    url=self.cfg.target_url, method=self.cfg.method,
                    parameter_name=param.name, parameter_location=param.location,
                    technique=r.technique, confidence=r.confidence,
                    severity=r.severity, dbms_hint=r.dbms_hint, signal=r.signal,
                    payload=r.payload, baseline_request=r.baseline_request,
                    injected_request=r.injected_request,
                    baseline_response_snippet=r.baseline_response_snippet,
                    injected_response_snippet=r.injected_response_snippet,
                    response_delta=r.response_delta,
                    remediation=build_remediation(r.technique, r.dbms_hint),
                    references=list(__import__("app.core.remediation",
                                               fromlist=["REFERENCES"]).REFERENCES),
                )
                self._emit("finding", finding=finding)
                self.stats["findings"] += 1
                self._log(f"⚠ {finding.summary()}")

            done += 1
            self._emit("progress", done=done, total=total)
            self._write_state_tick(done, total)

        self.stats["requests"] = self.stats["requests"]  # final
        self._emit("status",
                   message="Stopped" if self.cancelled() else "Finished")
        self._log(f"Scan complete: {self.stats['requests']} requests, "
                  f"{self.stats['findings']} findings, {self.stats['errors']} errors")
        self._emit("scan_finished")

    def _write_state_tick(self, done: int, total: int) -> None:
        self._emit("state", done=done, total=total)
