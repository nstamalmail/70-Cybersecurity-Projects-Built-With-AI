#!/usr/bin/env python3
"""GUI smoke test for XPT: instantiate the app off-screen and exercise paths."""

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

    from app.gui.main_window import XptApp
    app = XptApp(root)

    app._load_sample_config()
    f = {
        "severity": "high", "xss_type": "reflected", "context": "html_body",
        "parameter_location": "query", "parameter_name": "q",
        "payload": "<script>alert(1)</script>", "encoding_applied": "none",
        "browser_confirmed": False, "confirmation_method": "reflection",
        "signal": "test signal", "url": "http://x/", "method": "GET",
        "request": "r", "response_snippet": "v", "reflection_snippet": "s",
        "remediation": "encode", "references": [],
    }
    app.findings_tab.add_finding(f)
    root.update_idletasks()
    root.update()

    ok = bool(app.params_tab.get_all())
    app.state.log_memory("GUI smoke test executed")
    root.destroy()
    print("[PASS] GUI smoke test" if ok else "[FAIL] GUI smoke test")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
