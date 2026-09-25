"""Network interface discovery via GetAdaptersInfo (iphlpapi.dll).

Windows-only by design; import-guarded so non-Windows machines get a
clear error instead of an obscure ctypes failure.

Struct note (memory.md gotcha #1): the Windows header declares
    CHAR AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];   // 256 + 4 = 260
    CHAR Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]; // 128 + 4 = 132
Buffer sizes here MUST match, otherwise every field after them is
misaligned and the adapter list comes back as garbage.
"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import sys

if sys.platform != "win32":  # pragma: no cover - platform guard
    raise NotImplementedError(
        "core.interface requires Windows (uses iphlpapi.dll). "
        "The GUI/CLI must run on Windows."
    )

# ---------------------------------------------------------------- constants

MAX_ADAPTER_ADDRESS_LENGTH = 8
ADAPTER_NAME_BUF = 260            # MAX_ADAPTER_NAME_LENGTH + 4
ADAPTER_DESC_BUF = 132            # MAX_ADAPTER_DESCRIPTION_LENGTH + 4
IP_STRING_BUF = 4 * 4             # IP_ADDRESS_STRING.String is char[16]

ERROR_BUFFER_OVERFLOW = 111


# ---------------------------------------------------------------- structs

class _IP_ADDR_STRING(ctypes.Structure):
    pass


_IP_ADDR_STRING._fields_ = [
    ("Next", ctypes.POINTER(_IP_ADDR_STRING)),
    ("IpAddress", ctypes.c_char * IP_STRING_BUF),
    ("IpMask", ctypes.c_char * IP_STRING_BUF),
    ("Context", ctypes.c_uint32),
]


class IP_ADAPTER_INFO(ctypes.Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex", ctypes.c_uint32),
    ("AdapterName", ctypes.c_char * ADAPTER_NAME_BUF),
    ("Description", ctypes.c_char * ADAPTER_DESC_BUF),
    ("AddressLength", ctypes.c_uint32),
    ("Address", ctypes.c_uint8 * MAX_ADAPTER_ADDRESS_LENGTH),
    ("Index", ctypes.c_uint32),
    ("Type", ctypes.c_uint32),
    ("DhcpEnabled", ctypes.c_uint32),
    ("CurrentIpAddress", ctypes.POINTER(_IP_ADDR_STRING)),
    ("IpAddressList", _IP_ADDR_STRING),
    ("GatewayList", _IP_ADDR_STRING),
    ("DhcpServer", _IP_ADDR_STRING),
    ("HaveWins", ctypes.c_int32),
    ("PrimaryWinsServer", _IP_ADDR_STRING),
    ("SecondaryWinsServer", _IP_ADDR_STRING),
    ("LeaseObtained", ctypes.c_int64),   # time_t on x64
    ("LeaseExpires", ctypes.c_int64),
]

_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
_GetAdaptersInfo = _iphlpapi.GetAdaptersInfo
_GetAdaptersInfo.argtypes = [
    ctypes.POINTER(IP_ADAPTER_INFO),
    ctypes.POINTER(ctypes.c_uint32),
]
_GetAdaptersInfo.restype = ctypes.c_uint32

# Sanity: on x64 this must be 656 bytes (header-derived). If a future
# Python/SDK changes packing, fail loudly instead of parsing garbage.
_EXPECTED_SIZE = 656


# ---------------------------------------------------------------- helpers

def _cstr(raw: bytes) -> str:
    """Fixed-size char buffer -> trimmed native string."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _ip_of(entry: _IP_ADDR_STRING) -> str:
    return entry.IpAddress.split(b"\x00", 1)[0].decode("ascii", "replace")


def _mask_of(entry: _IP_ADDR_STRING) -> str:
    return entry.IpMask.split(b"\x00", 1)[0].decode("ascii", "replace")


def _netmask_to_prefix(mask: str) -> int:
    try:
        return bin(int(ipaddress.IPv4Address(mask))).count("1")
    except ipaddress.AddressValueError:
        return 0


# ---------------------------------------------------------------- public API

def list_interfaces() -> list[dict]:
    """Enumerate IPv4 adapters.

    Returns dicts:
      {name, description, ip, netmask, prefix, cidr, gateway, mac, has_gateway}
    """
    cb = ctypes.c_uint32(0)
    res = _GetAdaptersInfo(None, ctypes.byref(cb))
    if res not in (0, ERROR_BUFFER_OVERFLOW) or cb.value == 0:
        raise OSError(f"GetAdaptersInfo sizing failed: {res}")

    buf = ctypes.create_string_buffer(cb.value)
    res = _GetAdaptersInfo(
        ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)), ctypes.byref(cb)
    )
    if res != 0:
        raise OSError(f"GetAdaptersInfo failed: {res}")

    adapters: list[dict] = []
    node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)).contents
    while True:
        entry = _parse_adapter(node)
        if entry:
            adapters.append(entry)
        if not node.Next:
            break
        node = node.Next.contents
    return adapters


def _parse_adapter(node: IP_ADAPTER_INFO) -> dict | None:
    # First valid IPv4 on the adapter (it may hold several).
    entry = node.IpAddressList
    ip, mask = _ip_of(entry), _mask_of(entry)
    nxt = entry.Next
    while (not ip or ip == "0.0.0.0") and nxt:
        entry = nxt.contents
        ip, mask = _ip_of(entry), _mask_of(entry)
        nxt = entry.Next
    if not ip or ip == "0.0.0.0":
        return None

    gateway = _ip_of(node.GatewayList)
    if gateway == "0.0.0.0":
        gateway = ""

    mac = ""
    if node.AddressLength:
        mac = ":".join(f"{b:02X}" for b in node.Address[: node.AddressLength])

    prefix = _netmask_to_prefix(mask)
    cidr = ""
    if prefix:
        try:
            cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            cidr = ""

    return {
        "name": _cstr(node.AdapterName),
        "description": _cstr(node.Description),
        "ip": ip,
        "netmask": mask,
        "prefix": prefix,
        "cidr": cidr,
        "gateway": gateway,
        "mac": mac,
        "has_gateway": bool(gateway),
    }


def default_interface() -> dict | None:
    """First adapter with a gateway and a usable mask; skip loopback/APIPA.

    Selection rule from architecture.md §4.2.
    """
    for a in list_interfaces():
        if a["ip"].startswith("169.254."):
            continue                      # APIPA (cable unplugged etc.)
        if a["ip"] == "127.0.0.1":
            continue                      # loopback
        if not a["has_gateway"]:
            continue
        if not (8 <= a["prefix"] <= 32):
            continue
        return a
    return None


def hostname_for(ip: str, timeout: float = 0.25) -> str:
    """Best-effort reverse DNS; empty string on failure.

    Blocking — call from a worker thread only.
    """
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)
