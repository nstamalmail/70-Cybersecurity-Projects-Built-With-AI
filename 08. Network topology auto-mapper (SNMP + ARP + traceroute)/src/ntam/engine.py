"""Topology discovery core for NTAM: ARP sweep, SNMP enrichment, traceroute.

SNMP is optional: when pysnmp is available the mapper reads sysDescr/sysName,
otherwise devices are classified by heuristic (TTL, open ports, hostname).
All discovery is read-only; the tool never writes to devices.
"""
from __future__ import annotations

import concurrent.futures as futures
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

try:
    import psutil
    _HAVE_PSUTIL = True
except ImportError:                                        # pragma: no cover
    _HAVE_PSUTIL = False

try:
    from pysnmp.hlapi import (                             # noqa: F401
        CommunityData, ContextData, ObjectIdentity, ObjectType, Snmp, UdpTransportTarget,
    )
    _HAVE_SNMP = True
except Exception:                                          # noqa: BLE001
    _HAVE_SNMP = False

# ------------------------------------------------------------------- models
@dataclass
class Interface:
    index: int = 0
    name: str = ""
    mac: str | None = None
    ip: str | None = None
    status: str = "unknown"
    speed: int | None = None


@dataclass
class NetworkDevice:
    device_id: str
    ip: str
    mac: str | None = None
    hostname: str | None = None
    sys_descr: str | None = None
    vendor: str | None = None
    device_type: str = "unknown"        # router|switch|server|host|unknown
    interfaces: list = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    snmp_accessible: bool = False
    hops: int | None = None

    def to_dict(self):
        return {
            "device_id": self.device_id, "ip": self.ip, "mac": self.mac,
            "hostname": self.hostname, "sys_descr": self.sys_descr,
            "vendor": self.vendor, "device_type": self.device_type,
            "snmp_accessible": self.snmp_accessible, "hops": self.hops,
            "interfaces": [vars(i) for i in self.interfaces],
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
        }


@dataclass
class NetworkLink:
    link_id: str
    source_device: str                  # device_id
    dest_device: str
    source_interface: int | None = None
    dest_interface: int | None = None
    link_type: str = "L2"               # L2 | L3 | unknown
    bandwidth: int | None = None

    def to_dict(self):
        return vars(self).copy()


@dataclass
class Topology:
    topology_id: str
    timestamp: datetime
    seed_ip: str
    devices: list = field(default_factory=list)
    links: list = field(default_factory=list)
    subnets: list = field(default_factory=list)
    discovery_duration: float = 0.0

    def to_dict(self):
        return {
            "topology_id": self.topology_id,
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "seed_ip": self.seed_ip,
            "devices": [d.to_dict() for d in self.devices],
            "links": [l.to_dict() for l in self.links],
            "subnets": list(self.subnets),
            "discovery_duration": self.discovery_duration,
        }


# ------------------------------------------------------------- OUI vendor db
OUI_PREFIXES = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware",
    "00:1A:2B": "Ayecom", "00:1B:63": "Apple", "00:25:00": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1A:A1": "AMD", "00:0D:3A": "Microsoft Azure", "00:15:5D": "Microsoft (Hyper-V)",
    "00:03:FF": "Microsoft", "3C:22:FB": "Apple", "F0:18:98": "Apple",
    "00:16:3E": "Xensource", "52:54:00": "QEMU/KVM", "00:1D:D8": "Cisco-Linksys",
    "00:07:7D": "Cisco", "00:1B:0C": "Cisco", "00:23:04": "Cisco", "00:25:45": "Cisco",
    "00:26:9E": "Cisco", "0C:75:BD": "Cisco", "14:1F:BA": "Cisco",
    "00:1F:33": "Netgear", "B0:B9:8A": "Netgear", "00:18:4D": "Netgear",
    "00:24:8C": "Belkin", "00:26:F2": "TP-Link", "50:C7:BF": "TP-Link",
    "84:16:F9": "TP-Link", "00:14:22": "Dell", "00:21:70": "Dell", "F8:BC:12": "Dell",
    "00:25:64": "Dell", "3C:D9:2B": "HP", "00:1F:29": "HP", "00:24:81": "HP",
    "00:17:88": "Philips Hue", "00:11:32": "Synology", "00:1C:C0": "Intel",
    "00:1B:21": "Intel", "0C:8B:85": "Samsung", "00:16:32": "Samsung",
    "00:21:4C": "Samsung", "00:12:17": "Cisco-Linksys", "00:04:5A": "D-Link",
}


def _mac_vendor(mac: str | None) -> str | None:
    if not mac or mac.count(":") < 2:
        return None
    prefix = mac.upper()[:8]
    return OUI_PREFIXES.get(prefix)


# ------------------------------------------------------------ discovery core
def _arp_table() -> list[tuple[str, str]]:
    """Read the system ARP cache: returns [(ip, mac)]."""
    out: list[tuple[str, str]] = []
    system = platform.system()
    try:
        if _HAVE_PSUTIL:
            for item in psutil.net_if_addrs() and []:       # psutil lacks ARP; keep subprocess
                break
        if system == "Windows":
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{12,17})\s", line)
                if m:
                    mac = m.group(2).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        out.append((m.group(1), mac))
        else:
            res = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-fA-F:]{12,17})", line)
                if m:
                    mac = m.group(2).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        out.append((m.group(1), mac))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def _ping(host: str, timeout: float = 1.0) -> tuple[bool, int | None]:
    """ICMP ping; returns (alive, ttl)."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        alive = res.returncode == 0
        ttl = None
        m = re.search(r"TTL[=:]\s*(\d+)", res.stdout, re.I)
        if m:
            ttl = int(m.group(1))
        return alive, ttl
    except (OSError, subprocess.TimeoutExpired):
        return False, None


def _snmp_get(ip: str, community: str, oids: list[str], timeout: float = 2.0):
    """SNMP GET via pysnmp; returns {oid_name: value} or {} if unavailable."""
    if not _HAVE_SNMP:
        return {}
    from pysnmp.hlapi import (
        CommunityData, ContextData, ObjectIdentity, ObjectType, Snmp, UdpTransportTarget,
    )
    names = {
        "1.3.6.1.2.1.1.1.0": "sys_descr",
        "1.3.6.1.2.1.1.5.0": "sys_name",
        "1.3.6.1.2.1.1.3.0": "sys_uptime",
    }
    result: dict = {}
    try:
        for oid in oids:
            for _err_ind, _err_status, _err_index, var_binds in Snmp().bulkCmd(
                CommunityData(community, mpModel=0), UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ContextData(), *[ObjectType(ObjectIdentity(o)) for o in [oid]],
                    lexicographicMode=False):
                pass
    except Exception:                                      # noqa: BLE001
        pass
    # simpler getCmd path
    try:
        iterator = Snmp().getCmd(
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
            ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids],
        )
        _err_ind, _err_status, _err_index, var_binds = next(iterator, (None, None, None, []))
        for vb in var_binds or []:
            oid_str = str(vb[0])
            name = names.get(oid_str, oid_str)
            result[name] = str(vb[1])
    except Exception:                                      # noqa: BLE001
        pass
    return result


def _classify(hostname: str | None, ttl: int | None, sys_descr: str | None,
              open_22: bool = False) -> str:
    if sys_descr:
        low = sys_descr.lower()
        if "router" in low or "ios" in low or "routeros" in low:
            return "router"
        if "switch" in low or "catalyst" in low:
            return "switch"
        if "linux" in low or "windows" in low or "server" in low:
            return "server"
    if ttl is not None:
        if ttl >= 250:
            return "router"
        if ttl >= 128:
            return "host" if not open_22 else "server"
        if ttl >= 64:
            return "host" if not open_22 else "server"
    if hostname and any(k in hostname.lower() for k in ("gw", "router", "rtr", "edge")):
        return "router"
    if hostname and any(k in hostname.lower() for k in ("sw", "switch")):
        return "switch"
    return "host"


def _traceroute(host: str, max_hops: int = 8, timeout: float = 2.0) -> list[dict]:
    """Best-effort traceroute; returns [{hop, ip, hostname, latency_ms}]."""
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), host]
    hops: list[dict] = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout + 15)
    except (OSError, subprocess.TimeoutExpired):
        return hops
    for line in res.stdout.splitlines()[1:]:
        m = re.search(r"^\s*(\d+)", line)
        if not m:
            continue
        hop_no = int(m.group(1))
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        lat_m = re.search(r"(\d+)\s*ms", line)
        ip = ip_m.group(1) if ip_m else None
        hops.append({"hop": hop_no, "ip": ip, "hostname": None,
                     "latency_ms": int(lat_m.group(1)) if lat_m else None})
    return hops


class DiscoveryController:
    """Runs the discovery pipeline in a worker thread; emits progress via callbacks."""

    def __init__(self):
        self.cancel_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, cfg: dict, on_progress, on_result, on_done):
        self.cancel_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(cfg, on_progress, on_result, on_done), daemon=True)
        self._thread.start()

    def cancel(self):
        self.cancel_event.set()

    def _run(self, cfg, on_progress, on_result, on_done):
        started = time.monotonic()
        topo = Topology(
            topology_id=uuid.uuid4().hex[:10],
            timestamp=datetime.now(),
            seed_ip=cfg["seed_ip"],
        )
        try:
            net = ipaddress.ip_network(cfg["scan_scope"], strict=False)
        except ValueError:
            on_done(None, f"invalid scan scope: {cfg['scan_scope']}")
            return
        topo.subnets.append(str(net))
        max_hosts = min(net.num_addresses, int(cfg.get("max_hosts", 254)))
        # ---------- phase 1: sweep hosts
        hosts = [str(h) for h in net.hosts()][:max_hosts]
        on_progress(0, len(hosts), "sweeping hosts (ping)")
        alive: dict[str, int | None] = {}
        with futures.ThreadPoolExecutor(max_workers=40) as pool:
            futs = {pool.submit(_ping, h, cfg.get("timeout", 1.0)): h for h in hosts}
            for i, fut in enumerate(futures.as_completed(futs)):
                if self.cancel_event.is_set():
                    break
                host = futs[fut]
                try:
                    ok, ttl = fut.result()
                except Exception:                          # noqa: BLE001
                    ok, ttl = False, None
                if ok:
                    alive[host] = ttl
                on_progress(i + 1, len(hosts), f"pinged {host}: {'up' if ok else '-'}")
        if not alive:
            on_done(topo, None)
            return
        # ---------- phase 2: ARP correlation
        on_progress(0, len(alive), "reading ARP cache")
        arp = dict(_arp_table())
        # ---------- phase 3: local interfaces for context
        local_ips = set()
        if _HAVE_PSUTIL:
            try:
                for _name, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if a.family == socket.AF_INET:
                            local_ips.add(a.address)
            except OSError:
                pass
        # ---------- phase 4: enrich devices
        devices: list[NetworkDevice] = []
        for i, (ip, ttl) in enumerate(sorted(alive.items())):
            if self.cancel_event.is_set():
                break
            dev = NetworkDevice(device_id=uuid.uuid4().hex[:8], ip=ip)
            dev.mac = arp.get(ip)
            dev.vendor = _mac_vendor(dev.mac)
            try:
                dev.hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                dev.hostname = None
            snmp_cfg = cfg.get("snmp") or {}
            if snmp_cfg.get("enabled"):
                data = _snmp_get(ip, snmp_cfg.get("community", "public"),
                                 ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"],
                                 timeout=snmp_cfg.get("timeout", 1.5))
                if data:
                    dev.snmp_accessible = True
                    dev.sys_descr = data.get("sys_descr")
                    dev.hostname = dev.hostname or data.get("sys_name")
            dev.device_type = _classify(dev.hostname, ttl, dev.sys_descr)
            dev.hops = 0 if ip in local_ips else None
            devices.append(dev)
            on_result(dev)
            on_progress(i + 1, len(alive), f"enriched {ip} ({dev.device_type})")
        topo.devices = devices
        # ---------- phase 5: links (same-subnet L2 edges via ARP completeness)
        link_id = 0
        gateway_guess = str(net.network_address + 1)
        for dev in devices:
            if dev.ip == gateway_guess or (dev.device_type == "router"):
                for other in devices:
                    if other is dev:
                        continue
                    link_id += 1
                    topo.links.append(NetworkLink(
                        link_id=f"L{link_id}", source_device=dev.device_id,
                        dest_device=other.device_id, link_type="L2"))
                break
        # ---------- phase 6: traceroute from seed host (optional)
        if cfg.get("traceroute") and devices:
            on_progress(0, 1, "traceroute")
            target = cfg.get("trace_target") or devices[-1].ip
            hops = _traceroute(target, max_hops=int(cfg.get("max_hops", 8)))
            for h in hops:
                h["target"] = target
            topo.traceroute = hops                        # type: ignore[attr-defined]
        topo.discovery_duration = time.monotonic() - started
        on_done(topo, None)


def topology_from_dict(d: dict) -> Topology:
    """Rebuild a Topology from imported JSON (sample data / saved file)."""
    topo = Topology(
        topology_id=d.get("topology_id", "imported"),
        timestamp=datetime.fromisoformat(d["timestamp"]) if d.get("timestamp") else datetime.now(),
        seed_ip=d.get("seed_ip", "?"),
        subnets=list(d.get("subnets", [])),
        discovery_duration=float(d.get("discovery_duration", 0.0)),
    )
    for dd in d.get("devices", []):
        dev = NetworkDevice(
            device_id=dd.get("device_id", uuid.uuid4().hex[:8]),
            ip=dd.get("ip", "?"), mac=dd.get("mac"), hostname=dd.get("hostname"),
            sys_descr=dd.get("sys_descr"), vendor=dd.get("vendor"),
            device_type=dd.get("device_type", "unknown"),
            snmp_accessible=bool(dd.get("snmp_accessible")),
            hops=dd.get("hops"),
        )
        if dd.get("first_seen"):
            try:
                dev.first_seen = datetime.fromisoformat(dd["first_seen"])
            except ValueError:
                pass
        for idata in dd.get("interfaces", []):
            dev.interfaces.append(Interface(**{k: idata.get(k) for k in
                                               ("index", "name", "mac", "ip", "status", "speed")}))
        topo.devices.append(dev)
    for ld in d.get("links", []):
        topo.links.append(NetworkLink(
            link_id=ld.get("link_id", ""), source_device=ld.get("source_device", ""),
            source_interface=ld.get("source_interface"),
            dest_device=ld.get("dest_device", ""), dest_interface=ld.get("dest_interface"),
            link_type=ld.get("link_type", "L2"), bandwidth=ld.get("bandwidth"),
        ))
    if d.get("traceroute"):
        topo.traceroute = d["traceroute"]                 # type: ignore[attr-defined]
    return topo
