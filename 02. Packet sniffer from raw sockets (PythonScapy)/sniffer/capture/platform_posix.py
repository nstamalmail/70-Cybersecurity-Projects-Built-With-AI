"""POSIX interface enumeration for the capture engine."""

from __future__ import annotations

import socket
from typing import List


def list_interfaces_posix() -> List[dict]:
    """Return [{name, ip, desc}] using if_nameindex + SIOCGIFCONF."""
    out: List[dict] = []
    seen_names = set()

    # names first (works even without IPv4 configured)
    try:
        for _idx, name in socket.if_nameindex():
            seen_names.add(name)
            out.append({"name": name, "ip": "", "desc": name})
    except (OSError, AttributeError):
        pass

    # attach IPv4 addresses where available (SIOCGIFCONF)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            bufsize = 8192
            names = b"\0" * bufsize
            addr_bytes = s.getsockopt(socket.SOL_SOCKET, 0xFFFF, bufsize)  # macOS may differ
        finally:
            s.close()
    except OSError:
        addr_bytes = b""

    # SIOCGIFCONF via fcntl is the portable route; keep best-effort and fail soft
    ip_by_name = {}
    try:
        import fcntl
        import array
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            bufsize = 4096
            buf = array.array("B", b"\0" * bufsize)
            ifreq = fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iL", bufsize, buf.buffer_info()[0]))  # SIOCGIFCONF
            size = struct.unpack("iL", ifreq)[0]
            data = buf.tobytes()[:size]
            pos = 0
            while pos + 40 <= len(data):
                name = data[pos:pos + 16].split(b"\0", 1)[0].decode("ascii", "replace")
                sa_family = int.from_bytes(data[pos + 16:pos + 18], "little")
                raw = data[pos + 20:pos + 24]
                if sa_family == 2:                     # AF_INET
                    ip = socket.inet_ntop(socket.AF_INET, raw)
                    ip_by_name[name] = ip
                pos += 40
        finally:
            s.close()
    except Exception:
        pass

    for entry in out:
        entry["ip"] = ip_by_name.get(entry["name"], "")

    # non-loopback preference: loopback moved to end
    loopbacks = [e for e in out if e["name"].startswith(("lo", "lo0"))]
    real = [e for e in out if not e["name"].startswith(("lo", "lo0"))]
    return real + loopbacks
