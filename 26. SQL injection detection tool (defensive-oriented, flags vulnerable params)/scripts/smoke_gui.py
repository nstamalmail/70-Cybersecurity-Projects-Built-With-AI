#!/usr/bin/env python3
"""GUI smoke test: instantiate the app off-screen and exercise core paths.

Usage: python scripts/smoke_gui.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk


def main() -> int:
    try:
        root = tk.Tk()
        root.withdraw()
    except tk.TclError as exc:
        print(f"[!] cannot open display: {exc}")
        return 1

    from app.gui.main_window import SidtApp
    app = SidtApp(root)

    # exercise config load/apply + findings rendering
    app._load_sample_config()
    f = {
        "severity": "high", "parameter_location": "query",
        "parameter_name": "user", "technique": "error", "confidence": "high",
        "dbms_hint": "mysql", "signal": "test signal", "payload": "'",
        "url": "http://x/", "method": "GET", "baseline_request": "r",
        "injected_request": "i", "baseline_response_snippet": "b",
        "injected_response_snippet": "v", "response_delta": {},
        "remediation": "parameterize", "references": [],
    }
    app.findings_tab.add_finding(f)
    app.notebook.select(app.findings_tab)
    root.update_idletasks()
    root.update()

    ok = bool(app.params_tab.get_all())
    app.state.log_memory("GUI smoke test executed")
    root.destroy()
    print("[PASS] GUI smoke test" if ok else "[FAIL] GUI smoke test")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
