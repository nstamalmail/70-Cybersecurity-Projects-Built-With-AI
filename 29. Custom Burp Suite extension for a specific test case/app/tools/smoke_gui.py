#!/usr/bin/env python3
"""GUI smoke test for CBSEF: start bridge, inject a finding via HTTP,
verify the live table, confirm workflow, and pump the event loop."""

import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, ROOT)

import tkinter as tk


def main() -> int:
    try:
        root = tk.Tk()
        root.withdraw()
    except tk.TclError as exc:
        print(f"[!] cannot open display: {exc}")
        return 1

    from app.gui.main_window import CbsefApp
    app = CbsefApp(root)

    # start bridge on an ephemeral-ish port and inject a finding via HTTP
    app.config_tab.port_var.set(8899)
    app._start_bridge()
    root.update()

    doc = {"test_case": "mass_assignment", "url": "/api/x", "method": "POST",
           "parameter": "is_admin", "confidence": "high",
           "signal_description": "smoke test finding"}
    req = urllib.request.Request(
        "http://127.0.0.1:8899/findings", data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        accepted = json.loads(resp.read()).get("accepted")

    # pump the loop so the app drains the queue
    deadline = time.time() + 4
    while time.time() < deadline:
        root.update()
        time.sleep(0.05)

    rows = len(app.findings_tab.tree.get_children())
    ok = accepted == 1 and rows == 1

    # confirm workflow
    first = app.findings_tab.tree.get_children()
    if first:
        app.findings_tab.tree.selection_set(first[0])
        app._set_status("confirmed")
        root.update()
        ok = ok and app.findings[0]["status"] == "confirmed"

    app._stop_bridge()
    app.state.log_memory("GUI smoke test executed")
    root.destroy()
    print("[PASS] GUI smoke test" if ok else f"[FAIL] GUI smoke test "
                                             f"(accepted={accepted}, rows={rows})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
