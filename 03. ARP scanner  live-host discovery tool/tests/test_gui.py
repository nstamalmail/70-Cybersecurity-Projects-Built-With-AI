"""GUI smoke tests — skipped without a display or on non-Windows cores."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

tkinter = pytest.importorskip("tkinter")

try:
    import ui.app  # noqa: F401  (raises NotImplementedError off-Windows)
    _CORE_OK = True
except NotImplementedError:
    _CORE_OK = False

pytestmark = [
    pytest.mark.skipif(not _CORE_OK, reason="core requires Windows (iphlpapi)"),
]


@pytest.fixture()
def root():
    import tkinter as tk

    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("No display available")
    r.withdraw()
    yield r
    r.destroy()


def test_app_constructs(root):
    from ui.app import ArpScannerApp

    app = ArpScannerApp(root)
    assert tuple(app.tree["columns"]) == ("ip", "mac", "vendor", "hostname")
    assert app.scan_btn.instate(["disabled"]) is False


def test_invalid_cidr_is_rejected(root):
    from ui.app import ArpScannerApp

    app = ArpScannerApp(root)
    app.cidr_var.set("not-a-cidr")
    assert app._selected_cidr() is None
    app.cidr_var.set("10.0.0.0/24")
    assert app._selected_cidr() == "10.0.0.0/24"


def test_sort_and_events_do_not_crash(root, monkeypatch):
    import tkinter.messagebox as mb

    from core.models import Host, ScanEvent
    from ui.app import ArpScannerApp

    # Route modal dialogs to a no-op so tests can't hang on a dialog.
    monkeypatch.setattr(mb, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(mb, "showinfo", lambda *a, **k: None)

    app = ArpScannerApp(root)
    app._handle_event(ScanEvent("host", Host(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")))
    app._handle_event(ScanEvent("host", Host(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:FE")))
    assert len(app.tree.get_children()) == 2

    app._sort_by("ip")
    app._sort_by("mac")          # unknown/empty values must not raise
    app._handle_event(ScanEvent("error", "boom"))  # must not raise

    app._handle_event(
        ScanEvent("done", _fake_result(["10.0.0.2", "10.0.0.1"]))
    )
    assert len(app.tree.get_children()) == 2
    first_row = app.tree.item(app.tree.get_children()[0], "values")
    assert first_row[0] == "10.0.0.1"  # done → re-sorted numerically


def _fake_result(ips: list[str]):
    from datetime import datetime

    from core.models import Host, ScanResult

    return ScanResult(
        cidr="10.0.0.0/24",
        started=datetime(2026, 1, 1, 0, 0, 0),
        finished=datetime(2026, 1, 1, 0, 0, 1),
        hosts=tuple(Host(ip=ip, mac="AA:BB:CC:DD:EE:FF") for ip in ips),
    )
