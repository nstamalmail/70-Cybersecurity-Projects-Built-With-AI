"""IOC extraction from behaviour telemetry.

Only *observed behaviour* produces indicators here (plus the sample hash), which
is what makes dynamic IOCs higher confidence than static string matches.
"""
from __future__ import annotations

import ipaddress
import re

_IOC_ORDER = {
    "ipv4": 0, "domain": 1, "url": 2, "port": 3, "file_path": 4, "dropped_file": 5,
    "registry": 6, "mutex": 7, "service": 8, "scheduled_task": 9, "command": 10,
    "user_agent": 11, "hash": 12, "dns_query": 13, "process": 14,
}

_SYSTEM_NOISE = re.compile(
    r"(?i)(\\windows\\(?:system32|syswow64|winsxs|assembly|fonts|inf|servicing)\\|"
    r"\\microsoft\\|\\schemas\\|w3\.org|microsoft\.com|windows\.com|msftncsi|"
    r"\.mui$|\.catalog$|\\temp\\~|\\appdata\\local\\microsoft\\)"
)

_DROPPED_EXT = re.compile(r"(?i)\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|jse|hta|lnk|jar|iso|img|zip|rar|7z)$")

_EXEC_IN_PATH = re.compile(r"(?i)\\(?:programdata|users\\[^\\]+\\appdata|users\\public|temp)\\[^\\]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|hta)$")


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def extract(session, *, include_private: bool = False, max_per_type: int = 400) -> list[dict]:
    """Compile the session's indicator list."""
    found: dict[tuple[str, str], dict] = {}

    def add(ioc_type: str, value: str, context: str = "", confidence: float = 0.6) -> None:
        value = str(value or "").strip().strip('"')
        if not value or len(value) > 500:
            return
        if ioc_type == "ipv4" and not include_private and not _is_external(value):
            return
        if ioc_type in ("file_path", "dropped_file", "registry") and _SYSTEM_NOISE.search(value):
            return
        key = (ioc_type, value.lower())
        if key in found:
            found[key]["confidence"] = min(1.0, found[key]["confidence"] + 0.05)
            if context and context not in found[key]["context"]:
                found[key]["context"] = (found[key]["context"] + "; " + context)[:220]
            return
        if sum(1 for k in found if k[0] == ioc_type) >= max_per_type:
            return
        found[key] = {
            "ioc_type": ioc_type,
            "value": value,
            "source": "dynamic",
            "sources": "dynamic",
            "confidence": confidence,
            "context": context[:220],
        }

    if session.sha256:
        add("hash", session.sha256, f"SHA-256 of {session.sample_name}", 0.95)
    if session.md5:
        add("hash", session.md5, f"MD5 of {session.sample_name}", 0.9)

    seen_ports: set[tuple[str, int]] = set()
    for event in session.events:
        event_type = event.event_type
        context = f"{event.label} by {event.process_name or 'unknown'} at {event.clock()}"

        if event_type in ("network", "http"):
            if event.dst_ip:
                if _is_external(event.dst_ip) or include_private:
                    add("ipv4", event.dst_ip, context, 0.7)
                else:
                    add("ipv4", event.dst_ip, context + " (internal)", 0.4)
            uri = event.path
            if uri and uri.lower().startswith("http"):
                add("url", uri, context, 0.7)
            host = event.arguments.get("host") or event.arguments.get("hostname")
            if host and not _is_alpha_ip(str(host)):
                add("domain", str(host), context, 0.65)
            if event.dst_port:
                key = (event.dst_ip or "", int(event.dst_port))
                if key not in seen_ports:
                    seen_ports.add(key)
                    add("port", str(event.dst_port), context, 0.45)
            ua = event.arguments.get("user-agent") or event.arguments.get("user_agent")
            if ua:
                add("user_agent", str(ua), context, 0.5)

        elif event_type == "dns":
            query = str(event.arguments.get("query") or "").strip()
            if query:
                add("dns_query", query, context, 0.6)
                if "." in query and not query.endswith("."):
                    add("domain", query, context, 0.55)

        elif event_type in ("file_write", "file_rename", "dropped_file"):
            if event.path:
                add("file_path", event.path, context, 0.5)
                if _DROPPED_EXT.search(event.path):
                    add("dropped_file", event.path, context, 0.75)
                if event.sha256:
                    add("hash", event.sha256, f"dropped file {event.path}", 0.85)
            if _EXEC_IN_PATH.search(event.path or ""):
                add("dropped_file", event.path, context + " (user-writable location)", 0.8)

        elif event_type in ("registry_set", "registry_delete"):
            if event.path:
                add("registry", event.path, context, 0.6)
            value_data = event.arguments.get("value_data")
            if isinstance(value_data, str) and value_data and _EXEC_IN_PATH.search(value_data):
                add("dropped_file", value_data, context + " (autostart payload)", 0.75)

        elif event_type == "service_create":
            name = event.arguments.get("service_name")
            if name:
                add("service", str(name), context, 0.8)
            binary = event.arguments.get("binary_path")
            if binary:
                add("dropped_file", str(binary), context, 0.7)

        elif event_type == "task_create":
            name = event.arguments.get("task_name")
            if name:
                add("scheduled_task", str(name), context, 0.8)
            command = event.arguments.get("command")
            if command:
                add("command", str(command), context, 0.7)

        elif event_type == "shell":
            command = event.arguments.get("command_line") or event.data
            if command:
                add("command", str(command), context, 0.7)

        elif event_type == "process_create":
            command = event.arguments.get("command_line")
            if command:
                add("command", str(command), context, 0.55)
            if event.process_name:
                add("process", event.process_name, context, 0.3)

        elif event_type in ("api_call", "module_load"):
            mutex = event.arguments.get("mutex") or event.arguments.get("name")
            if mutex and str(mutex).lower().startswith(("global\\", "local\\")):
                add("mutex", str(mutex), context, 0.6)

    rows = list(found.values())
    rows.sort(key=lambda r: (_IOC_ORDER.get(r["ioc_type"], 99), -r["confidence"], r["value"]))
    return rows


def _is_alpha_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def stats(iocs: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc["ioc_type"]] = counts.get(ioc["ioc_type"], 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def defang(value: str) -> str:
    out = str(value)
    out = re.sub(r"(?i)^https:", "hxxps:", out)
    out = re.sub(r"(?i)^http:", "hxxp:", out)
    out = out.replace("://", "[://]")
    out = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", out)
    out = re.sub(r"\.(?=[a-z]{2,})", "[.]", out, flags=re.I)
    out = out.replace("@", "[@]")
    return out
