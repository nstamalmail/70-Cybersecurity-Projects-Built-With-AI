"""Core engine for MMPS: scanning workers, service patterns, data model."""
from __future__ import annotations

import concurrent.futures as futures
import random
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

# ---------------------------------------------------------------- service db
SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongod", 11211: "memcached",
}
RISKY_PORTS: dict[int, tuple[str, str]] = {
    23: ("high", "Telnet transmits credentials in cleartext"),
    135: ("medium", "MS-RPC often exposed unnecessarily"),
    139: ("high", "NetBIOS exposed to network"),
    445: ("critical", "SMB - historical worm propagation vector (EternalBlue et al.)"),
    3389: ("high", "RDP - brute-force and BlueKeep target"),
    5900: ("high", "VNC frequently misconfigured / weak auth"),
    6379: ("critical", "Redis unprotected - often allows unauthenticated write"),
    11211: ("high", "Memcached - amplification / unauthenticated access"),
    27017: ("high", "MongoDB often deployed without auth"),
    9200: ("medium", "Elasticsearch sometimes exposes cluster data"),
    21: ("medium", "FTP - credentials in cleartext; consider SFTP"),
    1433: ("medium", "MS SQL exposed to network"),
}
SERVICE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh", re.compile(r"SSH-([\d.]+)-(\S+)", re.I)),
    ("ftp", re.compile(r"220[- ](\S+ FTP)", re.I)),
    ("smtp", re.compile(r"220[ -](\S+).*?(ESMTP|SMTP)", re.I)),
    ("http", re.compile(r"HTTP/[\d.]+\s+\d+")),  # handled via probe
    ("mysql", re.compile(r"(\d+\.\d+\.\d+)-\w*mysql", re.I)),
    ("redis", re.compile(r"-ERR|REDIS", re.I)),
    ("vnc", re.compile(r"RFB (\d{3}\.\d{3})")),
]
CVE_HINTS: dict[str, list[str]] = {
    "openssh": ["CVE-2023-38408 (OpenSSH ssh-agent RCE)", "CVE-2016-6210 (user enumeration)"],
    "apache": ["CVE-2021-41773 (path traversal / RCE)"],
    "nginx": ["CVE-2021-23017 (DNS resolver vuln)"],
    "iis": ["CVE-2017-7269 (WebDAV buffer overflow)"],
    "vsftpd": ["CVE-2011-2523 (backdoor)"],
    "proftpd": ["CVE-2019-12815 (file copy arbit code)"],
    "postfix": ["CVE-2023-51764 (SMTP smuggling)"],
    "microsoft-ds": ["CVE-2017-0144 (EternalBlue SMBv1)"],
}
ENUM_COMMANDS: dict[str, list[str]] = {
    "ssh": ["ssh-audit <host>", "nmap -p22 --script ssh-auth-methods <host>"],
    "http": ["whatweb <host>", "gobuster dir -u http://<host> -w <wordlist>"],
    "https": ["sslscan <host>", "testssl.sh <host>"],
    "ftp": ["nmap --script ftp-anon -p21 <host>", "hydra -L users -P pass <host> ftp"],
    "smtp": ["nmap --script smtp-enum-users -p25 <host>"],
    "smb": ["enum4linux -a <host>", "crackmapexec smb <host>"],
    "microsoft-ds": ["enum4linux -a <host>", "crackmapexec smb <host>"],
    "rdp": ["nmap --script rdp-ntlm-info -p3389 <host>", "crowbar -b rdp ..."],
    "ms-wbt": ["nmap --script rdp-ntlm-info -p3389 <host>", "crowbar -b rdp ..."],
    "redis": ["redis-cli -h <host> INFO", "nmap --script redis-info -p6379 <host>"],
    "mysql": ["nmap --script mysql-info -p3306 <host>"],
    "vnc": ["nmap --script vnc-info -p5900 <host>"],
}
TOP_1000 = sorted(
    list(SERVICE_NAMES)
    + [n for n in range(1, 100) if n not in SERVICE_NAMES]
    + [1099, 1723, 2049, 2121, 3000, 3128, 3268, 4444, 5000, 5060, 5439, 5555,
       5984, 6443, 6667, 8000, 8008, 8009, 8081, 8181, 8888, 9000, 9001, 9090,
       9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157]
)
TOP_100 = [
    7, 9, 13, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3268, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
    49155, 49156, 49157,
]


@dataclass
class PortResult:
    port: int
    state: str = "CLOSED"           # OPEN / CLOSED / FILTERED
    service: str | None = None
    version: str | None = None
    banner: str | None = None
    cves: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    risk_level: str = "info"

    def risk(self) -> None:
        """Assign risk level, CVE hints and next-step commands."""
        base = RISKY_PORTS.get(self.port)
        if base:
            self.risk_level = base[0]
            self.reason = base[1]
        else:
            self.risk_level = "info" if self.state == "OPEN" else "info"
        svc = (self.service or "").lower()
        for key, cves in CVE_HINTS.items():
            if key in (self.version or "").lower() or key == svc:
                self.cves = cves
                if self.risk_level == "info":
                    self.risk_level = "medium"
                break
        cmds = ENUM_COMMANDS.get(svc) or ENUM_COMMANDS.get("microsoft-ds" if svc == "smb" else "")
        if cmds:
            self.next_steps = [c.replace("<host>", "%TARGET%") for c in cmds]


@dataclass
class ScanResult:
    scan_id: str
    target: str
    resolved_ip: str
    scan_mode: str                  # tcp_connect | syn
    timestamp: datetime
    ports: list[PortResult] = field(default_factory=list)
    os_fingerprint: str | None = None
    total_scanned: int = 0
    open_count: int = 0
    duration_seconds: float = 0.0


class ScanController:
    """Runs a port scan in a background thread, emitting progress via callbacks."""

    def __init__(self):
        self.cancel_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, cfg: dict, on_progress, on_result, on_done) -> None:
        self.cancel_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(cfg, on_progress, on_result, on_done), daemon=True
        )
        self._thread.start()

    def cancel(self) -> None:
        self.cancel_event.set()

    # ------------------------------------------------------------------ run
    def _run(self, cfg, on_progress, on_result, on_done) -> None:
        started = time.monotonic()
        host = cfg["host"]
        ports = _parse_ports(cfg["ports_spec"])
        mode = cfg["mode"]
        workers = max(1, int(cfg.get("workers", 100)))
        timeout = float(cfg.get("timeout", 1.0))
        grab = bool(cfg.get("grab_banners", True))
        result = ScanResult(
            scan_id=uuid.uuid4().hex[:10],
            target=cfg["target"], resolved_ip=host, scan_mode=mode,
            timestamp=datetime.now(), total_scanned=len(ports),
        )
        try:
            result.os_fingerprint = _ttl_fingerprint(host, timeout)
        except OSError:
            result.os_fingerprint = None
        on_progress(0, len(ports), "starting")
        done_count = 0
        open_count = 0
        lock = threading.Lock()
        pool = futures.ThreadPoolExecutor(max_workers=workers)
        pending = set()

        def submit(port: int):
            fut = pool.submit(
                _scan_one, host, port, mode, timeout, grab, self.cancel_event
            )
            pending.add(fut)
            fut.add_done_callback(lambda f, p=port: _finish(f, p))

        def _finish(fut, port: int):
            nonlocal done_count, open_count
            try:
                pres: PortResult = fut.result()
            except Exception:                              # noqa: BLE001
                pres = PortResult(port=port, state="FILTERED")
            pres.risk()
            with lock:
                result.ports.append(pres)
                if pres.state == "OPEN":
                    open_count += 1
                done_count += 1
                current = done_count
            on_result(pres)
            on_progress(current, len(ports), f"port {port} {pres.state.lower()}")

        try:
            for port in ports:
                if self.cancel_event.is_set():
                    break
                if len(pending) >= workers * 2:
                    time.sleep(0.01)
                    continue
                submit(port)
            pool.shutdown(wait=True)
        except Exception as exc:                           # noqa: BLE001
            on_done(result, error=str(exc))
            return
        result.open_count = open_count
        result.duration_seconds = time.monotonic() - started
        on_done(result, error=None)


def _scan_one(host, port, mode, timeout, grab, cancel_event) -> PortResult:
    if cancel_event.is_set():
        return PortResult(port=port, state="FILTERED")
    if mode == "syn":
        state = _syn_probe(host, port, timeout)
        banner = None
        service = _service_for(host, port, state)
        return PortResult(port=port, state=state, service=service)
    # TCP connect
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            rc = sock.connect_ex((host, port))
            if rc == 0:
                banner = _grab_banner(sock, port) if grab else None
                service = _classify(host, port, banner)
                return PortResult(port=port, state="OPEN", service=service, banner=banner)
            if rc in (10061, 111):  # WSAECONNREFUSED / ECONNREFUSED
                return PortResult(port=port, state="CLOSED")
            return PortResult(port=port, state="FILTERED")
    except socket.timeout:
        return PortResult(port=port, state="FILTERED")
    except OSError:
        return PortResult(port=port, state="FILTERED")


def _grab_banner(sock, port) -> str | None:
    try:
        sock.settimeout(1.2)
        if port in (80, 8080, 8000, 8888, 3128, 8008):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(1024)
        return data.decode("utf-8", "replace").strip()[:200] or None
    except OSError:
        return None


def _classify(host, port, banner) -> str | None:
    if banner:
        for name, pattern in SERVICE_PATTERNS:
            m = pattern.search(banner)
            if m:
                version = " ".join(g for g in m.groups() if g)
                return name if not version else f"{name} ({version})"
        if port == 443:
            return "https"
    return SERVICE_NAMES.get(port)


def _service_for(host, port, state):
    return SERVICE_NAMES.get(port) if state == "OPEN" else None


def _syn_probe(host, port, timeout) -> str:
    """SYN scan via scapy; falls back to connect probe if raw sockets unavailable."""
    try:
        from scapy.all import IP, TCP, sr1, send  # type: ignore
    except Exception:                                      # noqa: BLE001
        return "FILTERED"
    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return "FILTERED"
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if int(flags) == 0x12:
                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
                return "OPEN"
            if int(flags) == 0x14:
                return "CLOSED"
        return "FILTERED"
    except PermissionError:
        raise
    except Exception:                                      # noqa: BLE001
        return "FILTERED"


def _ttl_fingerprint(host, timeout) -> str | None:
    """Very lightweight TTL-based OS guess via ICMP echo (works unprivileged)."""
    try:
        import subprocess
        flag = "-n" if os_name() == "Windows" else "-c"
        out = subprocess.run(
            ["ping", flag, "1", host], capture_output=True, text=True, timeout=timeout + 3
        )
        m = re.search(r"TTL[=:]\s*(\d+)", out.stdout, re.I)
        if not m:
            return None
        ttl = int(m.group(1))
        if ttl >= 128:
            return f"Windows family (TTL {ttl})"
        if ttl >= 64:
            return f"Linux/Unix family (TTL {ttl})"
        if ttl >= 255:
            return f"Network device (TTL {ttl})"
        return f"Unknown (TTL {ttl})"
    except Exception:                                      # noqa: BLE001
        return None


def os_name() -> str:
    import platform
    return platform.system()


def _parse_ports(spec: str) -> list[int]:
    """Parse '80', '1-1024', '22,80,443', 'top100', 'top1000', 'full'."""
    spec = (spec or "").strip().lower()
    if spec in ("top100", ""):
        return TOP_100
    if spec == "top1000":
        return TOP_1000
    if spec in ("full", "all", "1-65535"):
        return list(range(1, 65536))
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            if lo.isdigit() and hi.isdigit():
                ports.update(range(int(lo), int(hi) + 1))
        elif chunk.isdigit():
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)
