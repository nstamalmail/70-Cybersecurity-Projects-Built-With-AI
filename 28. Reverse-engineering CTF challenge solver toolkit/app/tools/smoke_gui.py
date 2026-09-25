#!/usr/bin/env python3
"""GUI smoke test for RECT: instantiate the app off-screen, load the sample
binary, save a case, and pump the event loop without entering mainloop."""

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

    from app.gui.main_window import RectApp
    app = RectApp(root)

    binpath = os.path.join(ROOT, "samples", "sample_challenge.bin")
    app.workspace_tab.binary_var.set(binpath)
    app.workspace_tab.name_var.set("smoke-test-case")
    app._load_binary()

    # pump the Tk event loop so the after() poller drains engine events
    deadline = time.time() + 5
    while time.time() < deadline:
        root.update()
        time.sleep(0.05)

    app.writeup_tab.flag_var.set("flag{smoke}")
    app.writeup_tab.solved_var.set(True)
    app._save_case()
    root.update()

    ok = app.challenge_id is not None
    app.state.log_memory("GUI smoke test executed")
    root.destroy()
    print("[PASS] GUI smoke test" if ok else "[FAIL] GUI smoke test")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
