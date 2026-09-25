"""Platform detection, privilege checks and elevation helpers.

Windows: ctypes admin check + ShellExecuteW 'runas' re-launch.
POSIX:   os.geteuid() == 0 check; no self-elevation (advise sudo).
"""

from __future__ import annotations

import os
import platform
import socket
import sys

IS_WINDOWS = platform.system().lower().startswith("win")


def is_admin() -> bool:
    """True if the current process has raw-socket-capable privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def elevate_windows() -> bool:
    """Re-launch this process with UAC 'runas'. Returns True if relaunched."""
    if not IS_WINDOWS:
        return False
    if os.environ.get("SNIFFER_ELEVATED") == "1":
        return False                                  # already tried; avoid loops
    try:
        import ctypes
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        script = sys.argv[0] if sys.argv[0].endswith(".py") else ""
        exe = sys.executable
        # Frozen exe: re-run the exe itself; source: re-run via pythonw
        if getattr(sys, "frozen", False):
            target = sys.argv[0]
            args = params
        else:
            target = exe
            args = f'"{script}" {params}' if script else params
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, args, None, 1  # SW_SHOWNORMAL
        )
        return rc > 32
    except Exception:
        return False


def elevate_or_exit() -> None:
    """Try to elevate; exit current instance if a new elevated one started."""
    if is_admin():
        return
    if elevate_windows():
        raise SystemExit(0)


def local_ips() -> "list[str]":
    """Best-effort list of this host's unicast IPv4 addresses."""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))            # no packets actually sent
                ips.append(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            pass
    return ips


def primary_ip() -> str:
    ips = local_ips()
    return ips[0] if ips else "127.0.0.1"
