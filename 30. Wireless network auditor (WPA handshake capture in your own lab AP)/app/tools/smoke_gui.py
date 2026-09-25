#!/usr/bin/env python3
"""GUI smoke test for WNA: fill scope, verify the synthetic capture, save a
target, and pump the event loop without entering mainloop."""

import os
import sys
import time

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

    from app.gui.main_window import WnaApp
    app = WnaApp(root)

    # scope: allowlist the synthetic AP
    app.scope_tab.allow_text.delete("1.0", "end")
    app.scope_tab.allow_text.insert("1.0", "02:11:22:33:44:55=WNA-Lab-AP")

    # build the synthetic capture and verify it
    from app.tools.capture_builder import build_handshake_cap
    cap = os.path.join(ROOT, "data", "smoke_lab.cap")
    build_handshake_cap(cap)
    app.capture_tab.path_var.set(cap)
    app._verify_capture()
    for _ in range(10):
        root.update()
        time.sleep(0.05)

    verified = app.verified is not None and app.verified.handshake_captured

    app._save_target()
    root.update()
    ok = verified and app.audit_id is not None

    app.state.log_memory("GUI smoke test executed")
    root.destroy()
    print("[PASS] GUI smoke test" if ok else f"[FAIL] GUI smoke test "
                                             f"(verified={verified})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
