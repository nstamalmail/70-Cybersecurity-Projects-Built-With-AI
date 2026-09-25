"""Headless self-test for CBSEF: engines, loopback bridge round-trip, report
export. Writes selftest_result.txt next to the executable.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

from app.config import get_base_dir
from app.core import engine as eng
from app.core.bridge import BridgeServer
from app.core.models import CandidateFinding, new_finding_id
from app.utils.state import StateStore


class _Result:
    def __init__(self):
        self.checks: list = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def summary(self) -> str:
        passed = sum(1 for c in self.checks if c["ok"])
        total = len(self.checks)
        status = "PASS" if passed == total else "FAIL"
        lines = [f"CBSEF self-test: {status} ({passed}/{total} checks)", ""]
        for c in self.checks:
            mark = "PASS" if c["ok"] else "FAIL"
            lines.append(f"[{mark}] {c['name']}" +
                         (f" — {c['detail']}" if c.get("detail") else ""))
        return "\n".join(lines)


def _post_json(url: str, doc: dict, token: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-CBSEF-Token"] = token
    req = urllib.request.Request(
        url, data=json.dumps(doc).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _get_json(url: str, token: str = "") -> dict:
    req = urllib.request.Request(
        url, headers={"X-CBSEF-Token": token} if token else {})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def run_selftest() -> int:
    result = _Result()
    base_dir = get_base_dir()
    result_path = os.path.join(base_dir, "selftest_result.txt")

    store = StateStore(base_dir)
    store.log_memory("self-test started (headless)")
    result.check("StateStore writes memory.md", os.path.exists(store.memory_path))

    # ---- mass-assignment probe builder --------------------------------------
    raw_req = ("POST /api/users HTTP/1.1\n"
               "Host: 127.0.0.1:8000\n"
               "Content-Type: application/json\n"
               "\n"
               '{"username": "demo", "email": "d@x.y"}')
    probes = eng.mass_assignment_probes(raw_req)
    result.check("mass-assignment probes built", len(probes) >= 3,
                 f"{len(probes)} probes")
    result.check("probe adds canary field", any(
        "is_admin" in p.raw_request for p in probes))

    # ---- mass-assignment analyzer (echoed field signal) ----------------------
    baseline_req = raw_req
    probe_req = probes[0].raw_request
    baseline_resp = {"status": 200, "len": 120, "body": '{"ok": true}'}
    probe_resp = {"status": 200, "len": 148,
                  "body": '{"ok": true, "is_admin": true}'}
    f = eng.analyze_mass_assignment(baseline_req, baseline_resp,
                                    probe_req, probe_resp)
    result.check("mass-assignment finding on echo", f is not None)
    result.check("finding has high/medium confidence",
                 f and f.confidence in ("high", "medium"),
                 f.confidence if f else "")
    result.check("finding has remediation", f and "allowlist" in f.remediation)

    # ---- analyzer does NOT flag a normal response ----------------------------
    probe_resp_neg = {"status": 200, "len": 120, "body": '{"ok": true}'}
    f2 = eng.analyze_mass_assignment(baseline_req, baseline_resp,
                                     probe_req, probe_resp_neg)
    result.check("no finding when server ignores canary", f2 is None)

    # ---- JWT analyzer ---------------------------------------------------------
    jwt_req = ("GET /api/me HTTP/1.1\nAuthorization: Bearer "
               "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiIxMjMifQ.")
    f3 = eng.analyze_jwt_confusion(jwt_req)
    result.check("jwt alg=none flagged", f3 is not None and "none" in
                 f3.signal_description)

    # ---- OAuth redirect analyzer ----------------------------------------------
    redirect_probe = ("GET /oauth/authorize?client_id=x&"
                      "redirect_uri=https%3A%2F%2Fevil.example.com HTTP/1.1")
    f4 = eng.analyze_oauth_redirect(
        "GET /oauth/authorize?client_id=x HTTP/1.1",
        redirect_probe,
        {"status": 302, "location": "https://evil.example.com/cb", "len": 0,
         "body": ""})
    result.check("oauth redirect bypass flagged", f4 is not None,
                 f4.signal_description if f4 else "")

    # ---- bridge round-trip ------------------------------------------------------
    out_q = __import__("queue").Queue()
    bridge = BridgeServer(port=0, token="selftest-token", findings_out=out_q,
                          log_fn=lambda m: None)
    bridge.start()
    try:
        health = _get_json(f"http://127.0.0.1:{bridge.actual_port}/health",
                           token="selftest-token")
        result.check("bridge health endpoint", health.get("ok") is True)

        doc = {"finding_id": new_finding_id(), "test_case": "mass_assignment",
               "url": "/api/users", "method": "POST", "endpoint": "/api/users",
               "parameter": "is_admin", "confidence": "high",
               "status": "candidate", "signal_description": "echoed is_admin"}
        r = _post_json(f"http://127.0.0.1:{bridge.actual_port}/findings", doc,
                       token="selftest-token")
        result.check("bridge accepts finding", r.get("accepted") == 1)

        f_in = out_q.get(timeout=5)
        result.check("finding received via bridge",
                     f_in.test_case == "mass_assignment" and
                     f_in.parameter == "is_admin")

        # token enforcement
        try:
            _post_json(f"http://127.0.0.1:{bridge.actual_port}/findings", doc,
                       token="wrong-token")
            result.check("bridge rejects bad token", False)
        except urllib.error.HTTPError as exc:
            result.check("bridge rejects bad token", exc.code == 403)
    finally:
        bridge.stop()

    # ---- report export -----------------------------------------------------------
    from app.core.report import export_all
    session = {"id": 1, "name": "selftest", "generated": "now",
               "test_case": "mass_assignment"}
    findings = [f.to_dict() if isinstance(f, CandidateFinding) else f
                for f in [f] if f]
    if not findings:
        findings = [doc]
    outdir = os.path.join(base_dir, "reports")
    paths = export_all(session, findings, outdir)
    result.check("HTML report exported", os.path.exists(paths["html"]))
    result.check("CSV report exported", os.path.exists(paths["csv"]))
    result.check("JSON report exported", os.path.exists(paths["json"]))

    store.log_memory("self-test finished (engines + bridge verified)")

    summary = result.summary()
    with open(result_path, "w", encoding="utf-8") as fh:
        fh.write(summary + "\n")

    print(summary)
    ok = all(c["ok"] for c in result.checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_selftest())
