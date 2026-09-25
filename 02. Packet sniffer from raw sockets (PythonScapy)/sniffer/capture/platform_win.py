"""Windows-specific capture plumbing: interface enumeration via GetAdaptersAddresses."""

from __future__ import annotations

import ctypes
import socket
import struct
from ctypes import wintypes
from typing import List, Optional


class _IpAdapterAddresses:
    """ctypes mirror of IP_ADAPTER_ADDRESSES (minimal, field offsets matter)."""


def list_interfaces_win() -> List[dict]:
    """Return [{name, ip, desc}] for adapters with an IPv4 unicast address."""
    import ctypes

    # Required buffer size query, then fill. Flags: skip noisy sources.
    GAA_FLAG_SKIP_ANYCAST = 0x0002
    GAA_FLAG_SKIP_MULTICAST = 0x0004
    GAA_FLAG_SKIP_DNS_SERVER = 0x0008
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER

    rc = -1
    for size in (16 * 1024, 64 * 1024, 256 * 1024):   # retry loop with growth
        buf = ctypes.create_string_buffer(size)
        bufsz = ctypes.c_ulong(size)
        rc = ctypes.windll.iphlpapi.GetAdaptersAddresses(
            socket.AF_INET, flags, None, buf, ctypes.byref(bufsz))
        if rc == 111:  # ERROR_BUFFER_OVERFLOW → retry with bigger buffer
            continue
        break

    adapters: List[dict] = []
    if rc != 0:
        return adapters

    # Walk the linked list manually. Offsets (x64) per IP_ADAPTER_ADDRESSES:
    #   IfIndex 4, ... FriendlyName 32, Description 40, FirstUnicastAddress 64
    # Layout differs between architectures; use pointer arithmetic via memmove
    # into a struct with matching layout (see _IPAA struct below).
    IPAA = ctypes.Structure
    # Minimal x64 layout (documented offsets):
    #   0   Length            (ulong)
    #   4   IfIndex           (ulong)
    #   8   Next              (ptr)
    #   16  AdapterName       (ptr)
    #   24  FirstUnicastAddress (ptr)
    #   ...
    #   48  Flags
    #   56  Mtu
    #   64  IfType
    #   ... FriendlyName at 96, Description at 104 ...
    # To stay robust across Windows versions, we instead parse with
    # ctypes.Structure definitions below.

    class SOCKADDR_LH(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [
                ("sa_family", ctypes.c_ushort),
                ("ipv4", ctypes.c_ubyte * 4),
            ]
        _anonymous_ = ("u",)
        _fields_ = [("u", _U), ("port_be", ctypes.c_ushort), ("pad", ctypes.c_ubyte * 6)]

    class IP_ADAPTER_UNICAST_ADDRESS_LH(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("Flags", ctypes.c_ulong),
            ("Next", ctypes.c_void_p),
            ("Address", ctypes.c_void_p),          # pointer to SOCKET_ADDRESS
        ]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR_LH)),
                    ("iSockaddrLength", ctypes.c_int)]

    # The real struct starts with Length/IfIndex/Next; we define a prefix
    # struct and read pointers by offset using ctypes.string_at + int.from_bytes
    def _ptr_at(base: int, off: int) -> int:
        raw = ctypes.string_at(base + off, 8)
        return int.from_bytes(raw, "little")

    OFFSET_IFINDEX = 4
    OFFSET_NEXT = 8
    OFFSET_FIRST_UNICAST = 24
    OFFSET_FRIENDLY = 96
    OFFSET_DESC = 104

    node = buf  # first IP_ADAPTER_ADDRESSES
    addr_int = ctypes.addressof(node)  # type: ignore[arg-type]
    seen = 0
    while addr_int and seen < 64:
        seen += 1
        try:
            length = int.from_bytes(ctypes.string_at(addr_int, 4), "little")
            if_index = int.from_bytes(ctypes.string_at(addr_int + 4, 4), "little")
            next_ptr = _ptr_at(addr_int, OFFSET_NEXT)
            unicast_ptr = _ptr_at(addr_int, OFFSET_FIRST_UNICAST)
            friendly_ptr = _ptr_at(addr_int, OFFSET_FRIENDLY)
            desc_ptr = _ptr_at(addr_int, OFFSET_DESC)
        except (OSError, MemoryError):
            break

        def read_wstr(ptr: int) -> str:
            if not ptr:
                return ""
            chars = []
            for i in range(0, 512, 2):
                try:
                    w = int.from_bytes(ctypes.string_at(ptr + i, 2), "little")
                except OSError:
                    break
                if w == 0:
                    break
                chars.append(chr(w))
            return "".join(chars)

        def read_unicast_ip(ptr: int) -> str:
            out = ""
            while ptr:
                try:
                    # SOCKET_ADDRESS { ptr sockaddr, len }
                    sa_ptr = _ptr_at(ptr, 0)
                    sa_len = int.from_bytes(ctypes.string_at(ptr + 8, 4), "little")
                    if sa_ptr and sa_len >= 16:
                        fam = int.from_bytes(ctypes.string_at(sa_ptr, 2), "little")
                        if fam == socket.AF_INET:
                            raw = ctypes.string_at(sa_ptr + 4, 4)
                            out = socket.inet_ntop(socket.AF_INET, raw)
                            break
                except OSError:
                    break
                try:
                    ptr = _ptr_at(ptr, 8)          # -> Next unicast entry
                except OSError:
                    break
            return out

        ip = read_unicast_ip(unicast_ptr)
        friendly = read_wstr(friendly_ptr)
        desc = read_wstr(desc_ptr)
        if ip:
            adapters.append({"name": friendly or f"if{if_index}", "ip": ip, "desc": desc or friendly})

        if not next_ptr:
            break
        addr_int = next_ptr

    return adapters
