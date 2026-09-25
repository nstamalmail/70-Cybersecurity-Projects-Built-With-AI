"""Ingest sources: tail files, listen on UDP, read Windows Event Logs, or accept
manually pasted logs.

File tailing is poll-based (no watchdog dependency): we track our read offset,
detect rotation/truncation via size and inode changes, and start at the end of
the file on attach (tail semantics) unless ``start_at_end`` is False.

The Windows Event Log source shells out to ``wevtutil`` (present on every
Windows since Vista) so the app keeps its zero-dependency promise — no
pywin32. It bookmarks the highest ``EventRecordID`` per channel and emits only
new events (tail semantics), parsing the XML output in-process.
"""
from __future__ import annotations

import os
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

from .events import RawEvent


@dataclass
class SourceConfig:
    id: str
    name: str
    type: str = "file"          # file | udp | winevt
    path: str = ""              # file source
    port: int = 514             # udp source
    enabled: bool = True
    start_at_end: bool = True   # file source: tail (True) or read whole file (False)
    channel: str = "Application"  # winevt source: Windows Event Log channel

    def describe(self) -> str:
        if self.type == "udp":
            return f"udp://0.0.0.0:{self.port}"
        if self.type == "winevt":
            return f"channel: {self.channel}"
        return self.path or "?"


class FileSource(threading.Thread):
    def __init__(self, cfg: SourceConfig, out_q: "queue.Queue[RawEvent]",
                 stop_evt: threading.Event, poll_interval: float = 0.5) -> None:
        super().__init__(name=f"file-{cfg.id}", daemon=True)
        self.cfg = cfg
        self.out_q = out_q
        self.stop_evt = stop_evt
        self.poll = poll_interval
        self._fh: Optional[object] = None
        self._offset = 0
        self._inode: Optional[tuple] = None
        self._status = "starting"

    @property
    def status(self) -> str:
        return self._status

    def run(self) -> None:
        while not self.stop_evt.is_set():
            try:
                self._tick()
            except Exception as exc:  # never die silently
                self._status = f"error: {exc}"
            self.stop_evt.wait(self.poll)
        self._close_fh()

    def _tick(self) -> None:
        path = self.cfg.path
        try:
            st = os.stat(path)
        except OSError:
            self._status = "missing file"
            self._close_fh()
            return
        inode = (getattr(st, "st_dev", 0), getattr(st, "st_ino", 0))
        if self._fh is None:
            self._fh = open(path, "rb")
            if self.cfg.start_at_end:
                self._offset = self._fh.seek(0, 2)  # tail: start at end
            else:
                self._offset = 0  # webtail "from the beginning": read existing content
            self._inode = inode
        elif inode != self._inode or st.st_size < self._offset:
            # rotation / truncation → reopen and read the new file from the start
            self._close_fh()
            self._fh = open(path, "rb")
            self._offset = 0
            self._inode = inode
        data = self._fh.read()
        if data:
            self._offset = self._fh.tell()
            self._emit_lines(data)
        self._status = "watching"

    def _emit_lines(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip():
                self._put(RawEvent(raw=line, source_name=self.cfg.name, source_type="file"))

    def _put(self, raw: RawEvent) -> None:
        try:
            self.out_q.put(raw, timeout=1.0)
        except queue.Full:
            pass  # drop under back-pressure rather than block the source

    def _close_fh(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


class UDPSource(threading.Thread):
    def __init__(self, cfg: SourceConfig, out_q: "queue.Queue[RawEvent]",
                 stop_evt: threading.Event) -> None:
        super().__init__(name=f"udp-{cfg.id}", daemon=True)
        self.cfg = cfg
        self.out_q = out_q
        self.stop_evt = stop_evt
        self._status = "starting"

    @property
    def status(self) -> str:
        return self._status

    def run(self) -> None:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.cfg.port))
            sock.settimeout(0.5)
            self._status = "listening"
            while not self.stop_evt.is_set():
                try:
                    data, _addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if line.strip():
                        try:
                            self.out_q.put(
                                RawEvent(raw=line, source_name=self.cfg.name,
                                         source_type="udp"),
                                timeout=1.0,
                            )
                        except queue.Full:
                            pass
        except OSError as exc:
            self._status = f"bind error: {exc}"
        finally:
            if sock is not None:
                sock.close()

    def stop(self) -> None:
        self.stop_evt.set()


# ---------------------------------------------------------------------------
# Windows Event Log source (wevtutil, stdlib only)
# ---------------------------------------------------------------------------

_WEVTUTIL = "wevtutil"
_WINEVT_PAGE = 100  # events fetched per poll (newest-first)
_LEVEL_NAMES = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}


def _local_name(el) -> str:
    """Local tag name, ignoring the Windows Event XML namespace."""
    tag = el.tag
    if isinstance(tag, str) and "}" in tag:
        return tag.rsplit("}", 1)[1]
    return str(tag)


def _decode_wevtutil(data: bytes) -> str:
    """wevtutil emits UTF-16LE when redirected on Windows; tolerate UTF-8 too."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-16", errors="replace")


def parse_wevtutil_xml(data: bytes) -> list[dict[str, Any]]:
    """Parse ``wevtutil qe <channel> /f:xml`` output into event dicts.

    Returns events in the order returned by wevtutil (newest first). Each dict
    carries ``record_id`` (EventRecordID), ``event_id``, ``provider``,
    ``computer``, ``channel``, ``time_created``, ``level`` (numeric), ``data``
    (EventData name→value), and ``message`` (rendered message, if requested
    with /r:true). Pure function — testable on any platform.
    """
    text = _decode_wevtutil(data)
    # Strip the XML declaration: ElementTree ignores encoding on str input, but
    # removing it removes all doubt (and avoids the known expat utf-16 gripe).
    text = text.lstrip()
    if text.startswith("<?xml"):
        end = text.find("?>")
        if end != -1:
            text = text[end + 2:]
    # wevtutil emits sibling <Event> elements with NO wrapping root — the
    # output is not a well-formed XML document. Wrap it so ElementTree can
    # parse it (harmless if a root already exists).
    try:
        root = ET.fromstring("<Events>" + text + "</Events>")
    except ET.ParseError:
        return []
    events: list[dict[str, Any]] = []
    for el in root.iter():
        if _local_name(el) == "Event":
            events.append(_parse_event_el(el))
    return events


def _parse_event_el(el) -> dict[str, Any]:
    ev: dict[str, Any] = {}
    for child in el:
        name = _local_name(child)
        if name == "System":
            for node in child:
                n = _local_name(node)
                if n == "Provider":
                    ev["provider"] = node.get("Name", "")
                elif n == "EventID":
                    ev["event_id"] = (node.text or "").strip()
                elif n == "TimeCreated":
                    ev["time_created"] = node.get("SystemTime", "")
                elif n == "EventRecordID":
                    ev["record_id"] = _as_int(node.text)
                elif n == "Computer":
                    ev["computer"] = (node.text or "").strip()
                elif n == "Channel":
                    ev["channel"] = (node.text or "").strip()
                elif n == "Level":
                    ev["level"] = (node.text or "").strip()
        elif name == "EventData":
            data: dict[str, str] = {}
            unnamed = 0
            for node in child:
                dname = node.get("Name")
                if not dname:
                    unnamed += 1
                    dname = f"Data{unnamed}"  # unnamed <Data> elements must not collide
                data[dname] = _collapse_ws("".join(node.itertext()))
            ev["data"] = data
        elif name == "RenderingInfo":
            for node in child:
                if _local_name(node) == "Message":
                    ev["message"] = "".join(node.itertext()).strip()
    return ev


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def format_winevt_line(ev: dict[str, Any]) -> str:
    """Render one event as a single Key=Value line the normalizer understands.

    The KVP parser then lands every field in ``fields`` (EventID, Provider,
    Computer, …) so existing rules (which match ``message`` or a field) work on
    Windows events unchanged. Level is mapped to its name ("Error", …) so the
    keyword severity inference classifies it correctly.
    """
    level = _LEVEL_NAMES.get(_as_int(ev.get("level")), str(ev.get("level", "")))
    parts = [
        f"EventID={ev.get('event_id', '')}",
        f"Provider={ev.get('provider', '')}",
        f"Level={level}",
        f"Computer={ev.get('computer', '')}",
        f"Channel={ev.get('channel', '')}",
        f"TimeCreated={ev.get('time_created', '')}",
    ]
    for key in sorted((ev.get("data") or {})):
        if key.lower() in ("message", "description", "binary"):
            continue  # message folded into Message below; Binary blobs are noise
        value = ev["data"][key]
        if value:
            parts.append(f"{key}={_quote_kvp(value)}")
    message = (ev.get("message") or "").strip()
    if message:
        parts.append(f"Message={_quote_kvp(_collapse_ws(message))}")
    return " ".join(parts)


def _quote_kvp(value: str) -> str:
    """Quote a KVP value; strip double quotes so the regex never breaks."""
    value = value.replace('"', "'").strip()
    if any(ch.isspace() for ch in value) or value == "":
        return f'"{value}"'
    return value


def _collapse_ws(text: str, limit: int = 1000) -> str:
    return re.sub(r"\s+", " ", text).strip()[:limit]


class WindowsEventLogSource(threading.Thread):
    """Polls a Windows Event Log channel via ``wevtutil`` and tails new events.

    Tail semantics: on attach it bookmarks the newest EventRecordID seen and
    only events with a higher record ID are emitted afterwards (same behaviour
    as FileSource starting at EOF). On non-Windows hosts it reports its status
    and exits instead of failing noisily.
    """

    def __init__(self, cfg: SourceConfig, out_q: "queue.Queue[RawEvent]",
                 stop_evt: threading.Event, poll_interval: float = 1.0) -> None:
        super().__init__(name=f"winevt-{cfg.id}", daemon=True)
        self.cfg = cfg
        self.out_q = out_q
        self.stop_evt = stop_evt
        self.poll = poll_interval
        self._last_id: Optional[int] = None
        self._status = "starting"
        self._available = os.name == "nt" and shutil.which(_WEVTUTIL) is not None

    @property
    def status(self) -> str:
        return self._status

    def run(self) -> None:
        if not self._available:
            self._status = "requires Windows + wevtutil"
            return
        while not self.stop_evt.is_set():
            try:
                self._tick()
            except Exception as exc:  # never die silently; keep polling
                self._status = f"error: {exc}"
            self.stop_evt.wait(self.poll)

    def _tick(self) -> None:
        xml, rendered = self._query()
        events = parse_wevtutil_xml(xml)  # newest first
        if not events:
            self._status = "watching (empty channel)"
            return
        max_id = max(_as_int(e.get("record_id")) for e in events)
        if self._last_id is None:
            self._last_id = max_id  # attach point: skip historical backlog
            self._status = f"watching (bookmark #{max_id})"
            return
        fresh = [e for e in events if _as_int(e.get("record_id")) > self._last_id]
        if fresh:
            self._last_id = max(max_id, self._last_id)
            # wevtutil returns newest first; emit oldest→newest so correlation
            # ordering stays roughly chronological.
            for ev in sorted(fresh, key=lambda e: _as_int(e.get("record_id"))):
                line = format_winevt_line(ev)
                self._put(RawEvent(raw=line, source_name=self.cfg.name,
                                   source_type="winevt"))
            self._status = f"watching ({len(fresh)} new -> #{self._last_id})"
        else:
            self._status = "watching" + ("" if rendered else " (no message rendering)")

    def _query(self) -> tuple[bytes, bool]:
        """Run wevtutil; returns (xml, rendered).

        ``/r:true`` renders human-readable messages but needs an RPC to the
        Event Log service and fails (rc=1722) in restricted sessions — retry
        without it so the source still works; messages then come from the
        structured EventData instead.
        """
        for rendered in (True, False):
            args = [_WEVTUTIL, "qe", self.cfg.channel,
                    "/f:xml", f"/c:{_WINEVT_PAGE}", "/rd:true"]
            if rendered:
                args.append("/r:true")
            try:
                proc = subprocess.run(args, capture_output=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired) as exc:
                if rendered:
                    continue
                raise RuntimeError(f"wevtutil qe {self.cfg.channel}: {exc}") from exc
            if proc.returncode == 0:
                return proc.stdout, rendered
            if not rendered:
                err = proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                raise RuntimeError(f"wevtutil qe {self.cfg.channel}: rc={proc.returncode} {err}")
        return b"", False  # unreachable

    def _put(self, raw: RawEvent) -> None:
        try:
            self.out_q.put(raw, timeout=1.0)
        except queue.Full:
            pass  # drop under back-pressure rather than block the source


class SourceManager:
    """Owns the live ingest threads. Manual text can be pushed at any time."""

    def __init__(self, out_q: "queue.Queue[RawEvent]", stop_evt: threading.Event,
                 poll_interval: float = 0.5) -> None:
        self.out_q = out_q
        self.stop_evt = stop_evt
        self.poll_interval = poll_interval
        self._threads: dict[str, threading.Thread] = {}
        self._sources: dict[str, SourceConfig] = {}
        self._src_stop: dict[str, threading.Event] = {}

    # -------------------------------------------------------------- lifecycle
    def add_source(self, cfg: SourceConfig) -> None:
        if cfg.id in self._threads:
            return
        self._sources[cfg.id] = cfg
        src_stop = threading.Event()
        self._src_stop[cfg.id] = src_stop
        if cfg.type == "udp":
            t: threading.Thread = UDPSource(cfg, self.out_q, src_stop)
        elif cfg.type == "winevt":
            t = WindowsEventLogSource(cfg, self.out_q, src_stop, self.poll_interval)
        else:
            t = FileSource(cfg, self.out_q, src_stop, self.poll_interval)
        self._threads[cfg.id] = t
        if cfg.enabled:
            t.start()

    def remove_source(self, source_id: str) -> None:
        self.stop_source(source_id)
        self._threads.pop(source_id, None)
        self._sources.pop(source_id, None)
        self._src_stop.pop(source_id, None)

    def stop_source(self, source_id: str) -> None:
        ev = self._src_stop.get(source_id)
        if ev is not None:
            ev.set()
        t = self._threads.get(source_id)
        if t is not None:
            t.join(timeout=2.0)

    def start_source(self, source_id: str) -> None:
        t = self._threads.get(source_id)
        if t is not None and not t.is_alive():
            t.start()

    def start_source_all(self) -> None:
        for t in self._threads.values():
            if not t.is_alive():
                t.start()

    def stop_all(self) -> None:
        for ev in self._src_stop.values():
            ev.set()
        for t in self._threads.values():
            t.join(timeout=2.0)

    # ------------------------------------------------------------------ query
    def sources(self) -> list[SourceConfig]:
        return list(self._sources.values())

    def statuses(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for sid, t in self._threads.items():
            if hasattr(t, "status"):
                out[sid] = t.status  # type: ignore[attr-defined]
            elif t.is_alive():
                out[sid] = "running"
            else:
                out[sid] = "stopped"
        return out

    # ----------------------------------------------------------------- manual
    def ingest_text(self, text: str, source_name: str = "manual") -> int:
        """Push pasted text as raw events; returns how many lines were queued."""
        n = 0
        for line in text.splitlines():
            if line.strip():
                try:
                    self.out_q.put(
                        RawEvent(raw=line, source_name=source_name, source_type="manual"),
                        timeout=1.0,
                    )
                    n += 1
                except queue.Full:
                    break
        return n