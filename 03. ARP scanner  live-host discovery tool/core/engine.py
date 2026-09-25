"""SendARP-based live-host discovery engine.

Single Windows API dependency: SendARP from iphlpapi.dll. No Npcap, no
admin rights, no packet crafting. See architecture.md §4.3.
"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from core.interface import hostname_for
from core.models import Host, ScanConfig, ScanEvent, ScanResult
from core.oui import lookup_vendor

_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

_sendarp = _iphlpapi.SendARP
_sendarp.argtypes = [
    ctypes.c_uint32,                          # DestIP  (see _ip_to_u32)
    ctypes.c_uint32,                          # SrcIP   (0 = let stack pick)
    ctypes.POINTER(ctypes.c_uint8 * 6),       # out: MAC buffer
    ctypes.POINTER(ctypes.c_uint32),          # in/out: buffer length (bytes)
]
_sendarp.restype = ctypes.c_uint32


def _ip_to_u32(ip: str) -> int:
    """Dotted quad -> the DWORD SendARP expects.

    Gotcha (memory.md #2): SendARP's IPAddr is 'network byte order',
    i.e. the value a C program gets from inet_addr(). On x86 that is
    the u32 whose LITTLE-ENDIAN memory layout spells the octets:
    127.0.0.1 -> 0x0100007F (NOT 0x7F000001). Passing the plain
    big-endian int(IPv4Address(...)) probes byte-swapped addresses.
    """
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _format_mac(buf: ctypes.Array) -> str:
    return ":".join(f"{b:02X}" for b in buf)


class _CancellationToken:
    """Cooperative cancel flag shared with worker threads."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


def arp_probe(ip: str) -> str | None:
    """Resolve one IP via SendARP.

    Returns canonical MAC "AA:BB:CC:DD:EE:FF" on success, None otherwise.
    No retries, no exceptions for normal failure codes — offline hosts
    are the expected case, not an error.
    """
    mac_buf = (ctypes.c_uint8 * 6)()
    mac_len = ctypes.c_uint32(ctypes.sizeof(mac_buf))
    rc = _sendarp(_ip_to_u32(ip), 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
    if rc != 0:
        return None
    if mac_len.value < 6:
        return None
    return _format_mac(mac_buf)


def expand_targets(cidr: str, exclude_ip: str = "") -> list[str]:
    """CIDR -> sorted list of probeable host IPs.

    /0-/30: network and broadcast excluded. /31: both addresses probed
    (RFC 3021). /32: the single address. Explicit regardless of the
    Python version's ipaddress.hosts() quirks.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError(f"IPv4 only, got {cidr!r}")
    if net.prefixlen >= 31:
        ips = [str(net.network_address)]
        if net.prefixlen == 31:
            ips.append(str(net.broadcast_address))
    else:
        ips = [str(h) for h in net.hosts()]
    if exclude_ip and exclude_ip in ips:
        ips.remove(exclude_ip)
    return sorted(set(ips), key=lambda s: int(ipaddress.ip_address(s)))


def scan(
    config: ScanConfig,
    event_cb,
    cancel_token: _CancellationToken | None = None,
    interfaces: list[dict] | None = None,
) -> ScanResult:
    """Run one ARP sweep. Blocking; call from a worker thread.

    event_cb receives ScanEvent instances:
      start    -> {"cidr":…, "total":…}
      progress -> {"done":n, "total":n}
      host     -> Host
      done     -> ScanResult
      error    -> str (message); scan result still emitted where possible
    """
    token = cancel_token or _CancellationToken()
    started = datetime.now()

    try:
        targets = expand_targets(config.cidr)
    except ValueError as exc:
        event_cb(ScanEvent("error", f"Invalid CIDR: {exc}"))
        raise

    # Don't probe our own address — we already know we're alive.
    if interfaces:
        for a in interfaces:
            own = a.get("ip", "")
            if own and own in targets:
                targets.remove(own)
                break

    event_cb(ScanEvent("start", {"cidr": config.cidr, "total": len(targets)}))

    hosts: list[Host] = []
    lock = threading.Lock()
    done_count = 0

    def _worker(ip: str) -> None:
        nonlocal done_count
        if token.cancelled:
            return
        mac = arp_probe(ip)
        with lock:
            done_count += 1
            local_done, local_total = done_count, len(targets)
        if mac:
            host = Host(
                ip=ip,
                mac=mac,
                vendor=lookup_vendor(mac),
                hostname=hostname_for(ip),
            )
            with lock:
                hosts.append(host)
            event_cb(ScanEvent("host", host))
        if local_done % 10 == 0 or local_done == local_total:
            event_cb(ScanEvent("progress", {"done": local_done, "total": local_total}))

    with ThreadPoolExecutor(max_workers=max(1, config.max_workers)) as pool:
        futures = [pool.submit(_worker, ip) for ip in targets]
        for fut in futures:
            fut.result()  # workers never raise, but be strict

    result = ScanResult(
        cidr=config.cidr,
        started=started,
        finished=datetime.now(),
        hosts=tuple(hosts),
    )
    event_cb(ScanEvent("done", result))
    return result


def make_cancel_token() -> _CancellationToken:
    """Factory so the UI never imports engine internals beyond this."""
    return _CancellationToken()
