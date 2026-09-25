"""GUI smoke test: instantiate the workbench, run a scenario, switch every tab.

Run:  python scripts/gui_smoke.py   (exit 0 = pass)
Requires a display; on CI use xvfb-run.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.gui.app_window import Workbench


def main() -> int:
    app = Workbench()
    app.update()
    assert len(app.views) == 8, f"expected 8 tabs, got {len(app.views)}"

    # Exercise a full worker-thread run through the real event loop.
    app._on_run()
    deadline = time.time() + 60
    while (app._worker and app._worker.is_alive()) or not app._queue.empty():
        app.update()
        time.sleep(0.02)
        if time.time() > deadline:
            print("FAIL: worker did not finish in 60s")
            return 1
    app.update()
    if app.result is None:
        print("FAIL: no result after run")
        return 1
    c = app.result.verdict_counts
    if app.result.scenario != "c2_domain_fronting" or c["malicious"] == 0:
        print(f"FAIL: unexpected result {app.result.scenario} {c}")
        return 1

    # Switch through every tab and force redraws.
    for i in range(8):
        app.notebook.select(i)
        app.update()
        app.update_idletasks()

    # Flows table must be populated and filterable.
    flows_view = app.views[1]
    if not flows_view.tree.get_children():
        print("FAIL: flows table empty")
        return 1
    flows_view.filter_var.set("campaign")
    flows_view._refresh()
    app.update()

    app.destroy()
    print(f"GUI SMOKE PASSED — 8 tabs, {len(app.result.flows)} flows, verdicts {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
