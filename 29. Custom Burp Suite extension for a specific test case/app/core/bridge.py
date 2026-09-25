"""Loopback bridge server for CBSEF (architecture.md §3.1 Local Bridge).

A minimal HTTP server bound to 127.0.0.1 that the Burp extension (or any
local tool / curl) can push findings to:

    POST /findings        body: JSON CandidateFinding (or a list)
    GET  /findings        returns findings as JSON
    GET  /health          returns {"ok": true}

Security: loopback only + shared token check when set (X-CBSEF-Token).
The GUI drains a queue of received findings on its main thread.
"""

from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.config import BRIDGE_HOST
from app.core.models import CandidateFinding, new_finding_id


class BridgeServer:
    def __init__(self, port: int, token: str = "",
                 findings_out: "queue.Queue | None" = None,
                 log_fn=None):
        self.port = port
        self.token = token
        self.findings_out = findings_out or queue.Queue()
        self.log_fn = log_fn or (lambda msg: None)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.received_count = 0

    # ------------------------------------------------------------------ start
    def start(self) -> None:
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, code: int, payload: dict):
                data = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _auth_ok(self) -> bool:
                if not bridge.token:
                    return True
                return self.headers.get("X-CBSEF-Token", "") == bridge.token

            def do_GET(self):
                if self.path.startswith("/health"):
                    self._send(200, {"ok": True, "token_required": bool(bridge.token)})
                elif self.path.startswith("/findings"):
                    if not self._auth_ok():
                        self._send(403, {"error": "bad token"})
                        return
                    items = []
                    while True:
                        try:
                            f = bridge.findings_out.get_nowait()
                        except Exception:
                            break
                        items.append(f.to_dict())
                    self._send(200, {"findings": items})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                if not self.path.startswith("/findings"):
                    self._send(404, {"error": "not found"})
                    return
                if not self._auth_ok():
                    self._send(403, {"error": "bad token"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    raw = self.rfile.read(length).decode("utf-8", "replace")
                    doc = json.loads(raw)
                except Exception as exc:
                    self._send(400, {"error": f"bad json: {exc}"})
                    return
                items = doc if isinstance(doc, list) else [doc]
                accepted = 0
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    f = CandidateFinding(
                        finding_id=str(item.get("finding_id") or new_finding_id()),
                        test_case=str(item.get("test_case", "unknown")),
                        url=str(item.get("url", "")),
                        method=str(item.get("method", "")),
                        endpoint=str(item.get("endpoint", "")),
                        parameter=str(item.get("parameter", "") or ""),
                        confidence=str(item.get("confidence", "medium")),
                        status=str(item.get("status", "candidate")),
                        signal_description=str(item.get("signal_description", "")),
                        baseline_request=str(item.get("baseline_request", "")),
                        baseline_response=str(item.get("baseline_response", "")),
                        probe_request=str(item.get("probe_request", "")),
                        probe_response=str(item.get("probe_response", "")),
                        differential=item.get("differential") or {},
                        remediation=str(item.get("remediation", "")),
                    )
                    bridge.findings_out.put(f)
                    bridge.received_count += 1
                    accepted += 1
                bridge.log_fn(f"bridge: accepted {accepted} finding(s)")
                self._send(200, {"accepted": accepted})

        self._server = ThreadingHTTPServer((BRIDGE_HOST, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.log_fn(f"bridge listening on http://{BRIDGE_HOST}:{self.port}"
                    + (" (token required)" if self.token else ""))

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    @property
    def actual_port(self) -> int:
        return self._server.server_address[1] if self._server else self.port
