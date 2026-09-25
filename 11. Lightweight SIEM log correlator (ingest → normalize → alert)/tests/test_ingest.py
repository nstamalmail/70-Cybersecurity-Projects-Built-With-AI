"""Unit tests for ingest: Windows Event Log parsing + file start-at-end option.

Run:  python tests/test_ingest.py
"""
from __future__ import annotations

import os
import queue
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.events import RawEvent  # noqa: E402
from siem.ingest import (  # noqa: E402
    FileSource,
    SourceConfig,
    WindowsEventLogSource,
    format_winevt_line,
    parse_wevtutil_xml,
)
from siem.normalize import Normalizer  # noqa: E402

# A real-shaped wevtutil qe output fragment: namespaced XML, UTF-16 with BOM.
SAMPLE_XML = """<?xml version="1.0" encoding="utf-16"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
      <EventID>4625</EventID>
      <Version>0</Version>
      <Level>2</Level>
      <Task>12544</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8010000000000000</Keywords>
      <TimeCreated SystemTime="2026-09-07T12:00:00.000000Z"/>
      <EventRecordID>12345</EventRecordID>
      <Correlation/>
      <Execution ProcessID="4" ThreadID="88"/>
      <Channel>Security</Channel>
      <Computer>WIN-FILE1</Computer>
      <Security/>
    </System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-5-18</Data>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="TargetUserName">root</Data>
      <Data Name="WorkstationName">ATTACKER-PC</Data>
      <Data Name="IpAddress">192.168.1.50</Data>
      <Data Name="IpPort">49152</Data>
    </EventData>
    <RenderingInfo Culture="en-US">
      <Message>An account failed to log on. Subject: Security ID: S-1-5-18. Failure: the user has not been granted the requested logon type.</Message>
      <Level>Error</Level>
    </RenderingInfo>
  </Event>
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <Level>0</Level>
      <TimeCreated SystemTime="2026-09-07T12:00:01.000000Z"/>
      <EventRecordID>12346</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WIN-FILE1</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">alice</Data>
    </EventData>
  </Event>
</Events>
"""


def _run_file_source(cfg: SourceConfig, lines: list[str], wait: float = 0.4) -> list[RawEvent]:
    """Start a FileSource against a temp file and collect whatever it emits."""
    tmp = tempfile.mkdtemp(prefix="siem_fsrc_")
    path = os.path.join(tmp, "test.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    cfg.path = path  # the helper owns the file; point the config at it
    out_q: "queue.Queue[RawEvent]" = queue.Queue()
    stop = threading.Event()
    src = FileSource(cfg, out_q, stop, poll_interval=0.05)
    src.start()
    time.sleep(wait)
    stop.set()
    src.join(timeout=2)
    got: list[RawEvent] = []
    while not out_q.empty():
        got.append(out_q.get_nowait())
    return got


def test_parse_wevtutil_xml() -> bool:
    events = parse_wevtutil_xml(SAMPLE_XML.encode("utf-16"))
    ok = len(events) == 2
    ev = events[0]
    ok = ok and ev["record_id"] == 12345
    ok = ok and ev["event_id"] == "4625"
    ok = ok and ev["provider"] == "Microsoft-Windows-Security-Auditing"
    ok = ok and ev["computer"] == "WIN-FILE1"
    ok = ok and ev["channel"] == "Security"
    ok = ok and ev["time_created"] == "2026-09-07T12:00:00.000000Z"
    ok = ok and ev["data"]["TargetUserName"] == "root"
    ok = ok and ev["data"]["IpAddress"] == "192.168.1.50"
    ok = ok and "failed to log on" in ev["message"]
    ok = ok and events[1]["record_id"] == 12346
    print(f"[{'PASS' if ok else 'FAIL'}] parse_wevtutil_xml (UTF-16, namespaced, 2 events)")
    return ok


def test_format_and_normalize() -> bool:
    events = parse_wevtutil_xml(SAMPLE_XML.encode("utf-16"))
    line = format_winevt_line(events[0])
    ok = "EventID=4625" in line and "Provider=Microsoft-Windows-Security-Auditing" in line
    ok = ok and "Level=Error" in line  # numeric 2 mapped to its name for severity inference
    ok = ok and "TargetUserName=root" in line
    ok = ok and "Message=\"" in line
    ev = Normalizer().normalize(RawEvent(raw=line, source_name="win", source_type="winevt"))
    ok = ok and ev.source_type == "kvp"
    ok = ok and ev.fields.get("EventID") == "4625"
    ok = ok and ev.fields.get("Level") == "Error"
    ok = ok and ev.fields.get("Computer") == "WIN-FILE1"
    ok = ok and ev.severity == "ERROR"  # keyword inference sees the message + Level name
    ok = ok and "failed to log on" in ev.message
    print(f"[{'PASS' if ok else 'FAIL'}] format_winevt_line -> KVP normalizes with fields + severity")
    return ok


def test_file_source_start_at_end() -> bool:
    lines = ["line one", "line two", "line three"]
    cfg_tail = SourceConfig(id="t1", name="tail", type="file", start_at_end=True)
    got_tail = _run_file_source(cfg_tail, lines)
    ok = len(got_tail) == 0
    print(f"[{'PASS' if ok else 'FAIL'}] file source start_at_end=True emits nothing for existing content "
          f"(got {len(got_tail)})")
    cfg_full = SourceConfig(id="t2", name="full", type="file", start_at_end=False)
    got_full = _run_file_source(cfg_full, lines)
    ok = ok and len(got_full) == 3
    ok = ok and got_full[0].raw == "line one" and got_full[2].raw == "line three"
    ok = ok and all(r.source_type == "file" for r in got_full)
    print(f"[{'PASS' if ok else 'FAIL'}] file source start_at_end=False ingests all existing lines "
          f"(got {len(got_full)})")
    return ok


def test_winevt_tail_emits_only_new() -> bool:
    """Bookmark logic: first tick skips history, later ticks emit only new ids.

    ``_query`` is stubbed so the test is deterministic on any platform.
    """
    cfg = SourceConfig(id="w1", name="win", type="winevt", channel="Application")
    out_q: "queue.Queue[RawEvent]" = queue.Queue()
    src = WindowsEventLogSource(cfg, out_q, threading.Event())
    calls = {"n": 100}

    def fake_query():  # returns the last two records, newest first, ids rising
        xml = "".join(
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><EventRecordID>{rid}</EventRecordID></System>"
            f"<EventData><Data Name='TargetUserName'>alice</Data></EventData></Event>"
            for rid in (calls["n"], calls["n"] + 1)
        )
        return xml.encode("utf-8"), False

    src._query = fake_query

    src._tick()  # attach: bookmark 101, must NOT emit history
    ok = out_q.empty() and src._last_id == 101
    print(f"[{'PASS' if ok else 'FAIL'}] winevt attach bookmarks and skips backlog")

    calls["n"] += 1  # a new event (102) appears
    src._tick()
    fresh = []
    while not out_q.empty():
        fresh.append(out_q.get_nowait())
    ok = ok and len(fresh) == 1 and fresh[0].source_type == "winevt"
    ok = ok and "EventID=" in fresh[0].raw and "TargetUserName=alice" in fresh[0].raw
    ok = ok and src._last_id == 102
    print(f"[{'PASS' if ok else 'FAIL'}] winevt emits only new events as they appear (got {len(fresh)})")

    src._tick()  # nothing new → nothing emitted
    ok = ok and out_q.empty()
    print(f"[{'PASS' if ok else 'FAIL'}] winevt stays quiet when nothing new")
    return ok


def test_winevt_source_off_windows() -> bool:
    if os.name == "nt":
        print("[SKIP] winevt source runs for real on Windows - not exercised in unit test")
        return True
    cfg = SourceConfig(id="w1", name="win", type="winevt", channel="Application")
    out_q: "queue.Queue[RawEvent]" = queue.Queue()
    stop = threading.Event()
    src = WindowsEventLogSource(cfg, out_q, stop)
    src.start()
    time.sleep(0.2)
    stop.set()
    src.join(timeout=2)
    ok = src.status.startswith("requires Windows")
    print(f"[{'PASS' if ok else 'FAIL'}] winevt source off-Windows reports 'requires Windows' (got {src.status!r})")
    return ok


def main() -> int:
    checks = [
        test_parse_wevtutil_xml,
        test_format_and_normalize,
        test_file_source_start_at_end,
        test_winevt_tail_emits_only_new,
        test_winevt_source_off_windows,
    ]
    ok = True
    for check in checks:
        try:
            ok = check() and ok
        except Exception as exc:  # pragma: no cover
            ok = False
            print(f"[FAIL] {check.__name__} raised: {exc!r}")
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())