"""libpcap file format (v2.4) reader and writer — stdlib-only implementation.

Supports microsecond and nanosecond magic variants, both endiannesses on read;
writes little-endian microsecond files with configurable link type.
"""

from __future__ import annotations

import struct
import time
from typing import Iterator, List, Optional, Tuple

# link types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_RAW_IP_BSD = 228

# The magic is a byte-order test: read the first 4 bytes as little-endian.
# 0xA1B2C3D4 → file was written big-endian; 0xD4C3B2A1 → little-endian.
_MICRO_MAGIC_LE = 0xA1B2C3D4      # bytes on disk: a1 b2 c3 d4 (LE read → swapped value means LE file)
_MICRO_MAGIC_BE = 0xD4C3B2A1
_NANO_MAGIC_LE = 0xA1B23C4D
_NANO_MAGIC_BE = 0x4D3CB2A1

_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


class PcapFormatError(Exception):
    pass


class PcapWriter:
    """Streaming pcap writer — suitable for long captures (no buffering)."""

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 65535):
        self._fh = open(path, "wb")
        self.linktype = linktype
        self._fh.write(_GLOBAL_HEADER.pack(
            _MICRO_MAGIC_LE, 2, 4, 0, 0, snaplen, linktype))
        self.count = 0

    def write_packet(self, ts: float, data: bytes, orig_len: Optional[int] = None) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        if orig_len is None:
            orig_len = len(data)
        self._fh.write(_RECORD_HEADER.pack(sec, usec, len(data), orig_len))
        self._fh.write(data)
        self.count += 1

    def close(self) -> None:
        try:
            self._fh.flush()
        finally:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class PcapRecord:
    __slots__ = ("ts", "data", "orig_len")

    def __init__(self, ts: float, data: bytes, orig_len: int):
        self.ts = ts
        self.data = data
        self.orig_len = orig_len


class PcapReader:
    """Reads pcap files with any of the four standard magic variants."""

    def __init__(self, path: str):
        self._fh = open(path, "rb")
        gh = self._fh.read(24)
        if len(gh) < 24:
            raise PcapFormatError("not a pcap file (short header)")
        magic = struct.unpack_from("<I", gh, 0)[0]
        if magic == _MICRO_MAGIC_BE:
            self._endian = ">"
            self._divisor = 1_000_000
        elif magic == _MICRO_MAGIC_LE:
            self._endian = "<"
            self._divisor = 1_000_000
        elif magic == _NANO_MAGIC_BE:
            self._endian = ">"
            self._divisor = 1_000_000_000
        elif magic == _NANO_MAGIC_LE:
            self._endian = "<"
            self._divisor = 1_000_000_000
        else:
            self._fh.close()
            raise PcapFormatError(f"bad pcap magic 0x{magic:08x}")
        # fields after magic are (vmaj, vmin, tz, sig, snaplen, linktype)
        vals = struct.unpack(self._endian + "HHiIII", gh[4:24])
        self.version = (vals[0], vals[1])
        self.snaplen = vals[4]
        self.linktype = vals[5]

    def records(self) -> Iterator[PcapRecord]:
        while True:
            rh = self._fh.read(16)
            if len(rh) < 16:
                return
            ts_sec, ts_sub, incl_len, orig_len = _RECORD_HEADER.unpack(rh) \
                if self._endian == "<" else struct.unpack(">IIII", rh)
            data = self._fh.read(incl_len)
            if len(data) < incl_len:
                return                                    # truncated tail record
            yield PcapRecord(ts_sec + ts_sub / self._divisor, data, orig_len)

    def read_all(self) -> List[PcapRecord]:
        return list(self.records())

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
