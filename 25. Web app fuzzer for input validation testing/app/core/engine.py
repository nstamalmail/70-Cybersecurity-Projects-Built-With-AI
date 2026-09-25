"""FuzzEngine: orchestrates a full scan on a worker thread.

Emits events (dicts) onto an external queue.Queue:
    {"type": "status", "message": ...}
    {"type": "log", "message": ...}
    {"type": "progress", "done": n, "total": n}
    {"type": "finding", "finding": Finding}
    {"type": "scan_started"|"scan_finished"}
"""

from __future__ import annotations

import queue
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from app.core import detector as detector_mod
from app.core.http_client import HttpClient, error_label, same_host
from app.core.injector import build_request, discover_injection_points
from app.core.models import Finding, InjectionPoint, ScanConfig
from app.core.mutator import encoded_payload
from app.core.payloads import all_payloads


class FuzzEngine:
    def __init__(self, config: ScanConfig, event_queue: "queue.Queue"):
        self.config = config
        self.events = event_queue
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._pause.set()
        self.client = HttpClient(
            timeout=config.timeout, verify=config.verify_ssl,
            follow_redirects=config.follow_redirects, proxy=config.proxy,
            delay_ms=config.delay_ms,
        )
        self.analyzer = detector_mod.ResponseAnalyzer()
        self.stats = {"requests": 0, "errors": 0, "findings": 0}
        self._baselines: Dict[str, Tuple[int, str, float]] = {}
        self._alive = True

    # ------------------------------------------------------------------ API
    def start(self) -> None:
        threading.Thread(target=self._run, name="fuzz-engine", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._pause.set()

    def pause(self) -> None:
        self._pause.clear()

    def resume(self) -> None:
        self._pause.set()

    @property
    def running(self) -> bool:
        return self._alive

    def mark_done(self) -> None:
        self._alive = False

    # -------------------------------------------------------------- pipeline
    def _run(self) -> None:
        cfg = self.config
        self._emit("status", "Planning scan…")
        self._emit("scan_started")

        ips = [ip for ip in cfg.injection_points if ip.enabled]
        if not ips:
            ips = discover_injection_points(cfg)

        plan = self._build_plan(ips)
        if not plan:
            self._emit("log", "Nothing to fuzz: no injection points or payloads.")
            self._emit("scan_finished")
            self.mark_done()
            return

        total = len(plan)
        self._emit("log", f"Plan: {total} requests across {len(ips)} injection point(s), "
                          f"{len(cfg.categories)} category(ies), {len(cfg.encodings)} encoding(s).")
        self._emit("progress", 0, total)

        # Baseline + canary (cheap, serial).
        self._emit("status", "Probing baseline…")
        self._collect_baselines(ips)
        if self._stop.is_set():
            self._emit("scan_finished")
            self.mark_done()
            return

        # Fuzz.
        self._emit("status", "Fuzzing…")
        done = 0
        try:
            with ThreadPoolExecutor(max_workers=max(1, cfg.threads)) as pool:
                futures = {pool.submit(self._worker, task): task for task in plan}
                for fut in as_completed(futures):
                    if self._stop.is_set():
                        for f in list(futures):
                            f.cancel()
                        break
                    try:
                        fut.result()
                    except Exception as exc:  # noqa: BLE001 - worker must not die
                        self.stats["errors"] += 1
                        self._emit("log", f"worker error: {exc}")
                    done += 1
                    self._emit("progress", done, total)
        except Exception as exc:  # noqa: BLE001
            self._emit("log", f"pool error: {exc}")

        self._emit("status", "Finalizing…")
        self._emit("log",
                   f"Scan complete: {self.stats['requests']} requests, "
                   f"{self.stats['errors']} errors, {self.stats['findings']} findings.")
        self._emit("scan_finished")
        self.mark_done()

    def _build_plan(self, ips: List[InjectionPoint]) -> List[Tuple]:
        cfg = self.config
        payloads = all_payloads(cfg.categories, cfg.custom_payloads)
        plan: List[Tuple] = []
        for ip in ips:
            for cat, payload, technique in payloads:
                for enc in cfg.encodings:
                    plan.append((ip, cat, payload, technique, enc))
        # Cap.
        if cfg.max_requests > 0 and len(plan) > cfg.max_requests:
            plan = plan[: cfg.max_requests]
            self._emit("log", f"Plan capped at {cfg.max_requests} requests (max_requests).")
        # Shuffle to spread load; deterministic seed for reproducibility.
        rng = random.Random(20240909)
        rng.shuffle(plan)
        return plan

    def _collect_baselines(self, ips: List[InjectionPoint]) -> None:
        for ip in ips:
            if self._stop.is_set():
                return
            try:
                spec = build_request(self.config, ip, ip.value)
                resp, elapsed = self.client.send(spec)
                self._baselines[ip.key()] = (resp.status_code, resp.text, elapsed)
            except Exception as exc:  # noqa: BLE001
                self._baselines[ip.key()] = (0, "", 0.0)
                self.stats["errors"] += 1
                self._emit("log", f"baseline failed for {ip.key()}: {error_label(exc)}")

            # Canary: unique marker to learn reflection context.
            canary = f"wfz{random.randint(10**6, 10**7 - 1)}"
            try:
                spec = build_request(self.config, ip, canary)
                resp, _ = self.client.send(spec)
                reflected = canary in resp.text
                self._emit("log",
                           f"canary {ip.key()}: reflected={'yes' if reflected else 'no'} "
                           f"(status {resp.status_code})")
            except Exception as exc:  # noqa: BLE001
                self._emit("log", f"canary failed for {ip.key()}: {error_label(exc)}")

    # ----------------------------------------------------------------- worker
    def _worker(self, task: Tuple) -> None:
        ip, cat, payload, technique, enc = task
        if self._stop.is_set():
            return
        self._pause.wait()
        if self._stop.is_set():
            return

        encoded = encoded_payload(payload, enc)
        try:
            spec = build_request(self.config, ip, encoded)
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            return

        if not same_host(spec.url, self.config.target_url):
            self.stats["errors"] += 1
            self._emit("log", f"scope violation blocked: {spec.url}")
            return

        # Open-redirect detection needs to inspect the 3xx Location header,
        # so do not follow redirects for that category.
        if cat == "open_redirect" and self.config.follow_redirects:
            spec.allow_redirects = False

        baseline_status, baseline_body, baseline_elapsed = self._baselines.get(
            ip.key(), (0, "", 0.0))

        try:
            resp, elapsed = self.client.send(spec)
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            if self.config.time_based and "timeout" in error_label(exc).lower():
                # Timeout could indicate a sleep() executed.
                f = Finding(
                    category=cat, technique="time-based-blind", severity="high",
                    injection_kind=ip.kind, injection_name=ip.name,
                    payload=payload, encoding=enc, url=spec.url,
                    status=0, resp_len=0, resp_time_ms=(self.config.timeout + 15) * 1000,
                    evidence="request timed out (possible sleep())",
                    request=spec.preview(), response="<no response: timeout>",
                )
                self._record_finding(f)
            return

        findings = self.analyzer.analyze(
            spec, resp, elapsed, payload, enc, cat,
            baseline_body, baseline_status, baseline_elapsed,
            injection_kind=ip.kind, injection_name=ip.name)
        self.stats["requests"] += 1
        for f in findings:
            self._record_finding(f)

    def _record_finding(self, f: Finding) -> None:
        self.stats["findings"] += 1
        self._emit("finding", f)

    # ----------------------------------------------------------------- events
    def _emit(self, typ: str, *args) -> None:
        ev = {"type": typ}
        if typ == "status":
            ev["message"] = args[0]
        elif typ == "log":
            ev["message"] = args[0]
        elif typ == "progress":
            ev["done"], ev["total"] = args[0], args[1]
        elif typ == "finding":
            ev["finding"] = args[0]
        self.events.put(ev)


def run_scan_headless(cfg: ScanConfig, timeout: float = 120) -> tuple:
    """Blocking convenience wrapper for tests/CLI. Returns (findings, stats)."""
    q: "queue.Queue" = queue.Queue()
    engine = FuzzEngine(cfg, q)
    engine.start()
    findings: List[Finding] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ev = q.get(timeout=0.2)
        except queue.Empty:
            if not engine.running:
                break
            continue
        if ev["type"] == "finding":
            findings.append(ev["finding"])
    return findings, engine.stats