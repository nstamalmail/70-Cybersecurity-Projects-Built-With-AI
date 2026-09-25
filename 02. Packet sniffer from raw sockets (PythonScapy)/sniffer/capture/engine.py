"""Capture engines: live raw-socket capture and offline pcap replay.

Engines are pull-based workers running in a dedicated thread. They push
immutable Packet objects into a bounded queue (backpressure: drop newest),
so the GUI thread can never be blocked or flooded.
"""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Optional, Set

from ..models import Packet
from ..dissectors import dissect
from .pcap_file import PcapReader, LINKTYPE_ETHERNET

QUEUE_SIZE = 5000


class SnifferConfig:
    """Runtime options for a capture session."""

    def __init__(
        self,
        interface: str = "",                 # platform-specific selector (IP or ifname)
        promiscuous: bool = True,
        snaplen: int = 65535,
        bpf: str = "",                       # reserved: kernel filter (not yet wired)
        link_layer: bool = True,             # frames include an Ethernet header
        name: str = "",
    ) -> None:
        self.interface = interface
        self.promiscuous = promiscuous
        self.snaplen = snaplen
        self.bpf = bpf
        self.link_layer = link_layer
        self.name = name or interface or "any"


class CaptureEngine(ABC):
    """Common machinery: worker thread, bounded queue, counters."""

    def __init__(self, config: SnifferConfig):
        self.config = config
        self.queue: "queue.Queue[Packet]" = queue.Queue(maxsize=QUEUE_SIZE)
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()   # set = paused (socket stays open)
        self.dropped = 0
        self.captured = 0
        self._thread: Optional[threading.Thread] = None
        self._on_error: Optional[Callable[[str], None]] = None

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        self.stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_safe, name=f"capture-{self.config.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def pause(self) -> None:
        self.pause_event.set()

    def resume(self) -> None:
        self.pause_event.clear()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def on_error(self, cb: Callable[[str], None]) -> None:
        self._on_error = cb

    def _run_safe(self) -> None:
        try:
            self.capture_loop()
        except Exception as exc:                   # never kill the app silently
            if self._on_error:
                self._on_error(f"capture error: {exc}")

    # -- subclass contract ----------------------------------------------------
    @abstractmethod
    def open(self) -> None:
        """Acquire the raw socket. Must raise PermissionError if not elevated."""

    @abstractmethod
    def read_packet(self) -> Optional[tuple]:
        """Return (timestamp, raw_bytes, orig_len) or None if timed out."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""

    # -- loop -----------------------------------------------------------------
    def capture_loop(self) -> None:
        self.open()
        try:
            while not self.stop_event.is_set():
                if self.pause_event.is_set():
                    time.sleep(0.1)
                    continue
                got = self.read_packet()
                if got is None:
                    continue
                ts, raw, orig_len = got
                self.captured += 1
                pkt = Packet(number=self.captured, timestamp=ts, raw=raw, orig_len=orig_len)
                pkt = dissect(pkt, link_layer=self.config.link_layer)
                try:
                    self.queue.put_nowait(pkt)
                except queue.Full:
                    self.dropped += 1             # backpressure: drop newest
        finally:
            self.close()

    # -- helpers ----------------------------------------------------------------
    @staticmethod
    def _synth_eth(payload: bytes, ethertype: int) -> bytes:
        """Prepend a synthetic Ethernet header (Windows L3 raw-socket path)."""
        eth = b"\x00\x00\x00\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00" + struct.pack("!H", ethertype)
        return eth + payload


class RawSocketEngine(CaptureEngine):
    """Live capture: AF_PACKET (Linux) or SIO_RCVALL raw IP (Windows)."""

    def __init__(self, config: SnifferConfig):
        super().__init__(config)
        self.sock: Optional[socket.socket] = None
        self._is_windows = False
        try:
            import platform
            self._is_windows = platform.system().lower().startswith("win")
        except Exception:
            pass

    # -- Windows -------------------------------------------------------------
    def _open_windows(self) -> None:
        host_ip = self.config.interface or _default_host_ip()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except PermissionError as exc:
            raise PermissionError(
                "Administrator privileges required for raw sockets on Windows.") from exc
        except OSError as exc:
            raise OSError(f"cannot open raw socket: {exc}") from exc
        try:
            s.bind((host_ip, 0))
            # IP_HDRINCL is required before SIO_RCVALL on some stacks
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            SIO_RCVALL = 0x98000001
            RCVALL_ON = 1
            s.ioctl(SIO_RCVALL, RCVALL_ON)
            s.settimeout(0.5)
        except OSError as exc:
            s.close()
            raise PermissionError(
                f"SIO_RCVALL failed on {host_ip}: {exc}. Run as Administrator.") from exc
        self.sock = s
        self.config.interface = host_ip

    # -- POSIX ---------------------------------------------------------------
    def _open_posix(self) -> None:
        ifname = self.config.interface or None
        try:
            # AF_PACKET gives full L2 frames incl. VLAN (Linux, needs CAP_NET_RAW)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if ifname:
                s.bind((ifname, 0))
            s.settimeout(0.5)
            self.sock = s
            self.config.link_layer = True
            return
        except (AttributeError, OSError):
            pass
        # Fallback: raw IP sockets (macOS/BSD; L3 only → synthetic Ethernet)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError:
            pass
        s.settimeout(0.5)
        self.sock = s
        self.config.link_layer = False              # read_packet synthesizes

    def open(self) -> None:
        if self._is_windows:
            self._open_windows()
        else:
            self._open_posix()

    def read_packet(self):
        assert self.sock is not None
        try:
            data, _addr = self.sock.recvfrom(self.config.snaplen)
        except socket.timeout:
            return None
        except OSError:
            return None                              # closed / interrupted
        if not data:
            return None
        if not self.config.link_layer:
            probe = struct.unpack_from("!H", data, 12)[0] if len(data) >= 14 else 0
            if probe in (0x0800, 0x0806, 0x86DD, 0x8100):
                pass                                  # already an L2 frame
            else:
                ethertype = 0x0800 if (data[0] >> 4) == 4 else 0x86DD
                data = self._synth_eth(data, ethertype)
                self.config.link_layer = True
        return (time.time(), data, len(data))

    def close(self) -> None:
        if self.sock is not None:
            try:
                if self._is_windows:
                    try:
                        SIO_RCVALL = 0x98000001
                        RCVALL_OFF = 0
                        self.sock.ioctl(SIO_RCVALL, RCVALL_OFF)
                    except OSError:
                        pass
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class PcapFileEngine(CaptureEngine):
    """Offline replay of a .pcap file through the identical pipeline."""

    def __init__(self, config: SnifferConfig, path: str, speed: float = 0.0):
        super().__init__(config)
        self.path = path
        self.speed = speed                           # 0 = as fast as possible

    def open(self) -> None:
        self._reader = PcapReader(self.path)

    def read_packet(self):
        if self.pause_event.is_set():
            time.sleep(0.05)
            return None
        try:
            rec = next(self._iter)
        except StopIteration:
            self.stop_event.set()
            return None
        if self.speed > 0:
            time.sleep(1.0 / self.speed)
        if not self.config.link_layer:
            data = self._synth_eth(rec.data, 0x0800)
            return (rec.ts, data, rec.orig_len)
        return (rec.ts, rec.data, rec.orig_len)

    def capture_loop(self) -> None:
        self.open()
        self._iter = self._reader.records()
        try:
            while not self.stop_event.is_set():
                got = self.read_packet()
                if got is None:
                    continue
                ts, raw, orig_len = got
                self.captured += 1
                pkt = Packet(number=self.captured, timestamp=ts, raw=raw, orig_len=orig_len)
                pkt = dissect(pkt, link_layer=self.config.link_layer)
                try:
                    self.queue.put_nowait(pkt)
                except queue.Full:
                    self.dropped += 1
        finally:
            self.close()

    def close(self) -> None:
        r = getattr(self, "_reader", None)
        if r:
            r.close()


def _default_host_ip() -> str:
    """Best-effort default interface IP for the Windows raw bind."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def list_interfaces() -> "list[dict]":
    """Enumerate capture-capable interfaces for the GUI dropdown."""
    out = []
    try:
        import platform
        is_win = platform.system().lower().startswith("win")
    except Exception:
        is_win = False
    if is_win:
        try:
            from .platform_win import list_interfaces_win
            out = list_interfaces_win()
        except Exception:
            out = []
        if not out:
            from ..utils.platform import local_ips
            out = [{"name": ip, "ip": ip, "desc": ip} for ip in local_ips()]
    else:
        try:
            from .platform_posix import list_interfaces_posix
            out = list_interfaces_posix()
        except Exception:
            out = []
        if not out:
            try:
                out = [{"name": n, "ip": "", "desc": n}
                       for _idx, n in socket.if_nameindex()]
            except OSError:
                pass
    return out
