"""IOC extraction from the call stream and the report summary (architecture §3.7).

Everything the sample touched is recoverable from the arguments: dropped files,
registry keys written, hosts contacted, mutexes created, services installed.  The
extractor prefers the semantic argument name (``file_name`` optimistically beats
a regex sweep) and falls back to a scan of the raw argument text so unusual
sandbox builds still yield indicators.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.core.model import ApiCall

IPv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|io|info|biz|top|xyz|online|club|site|live|cc|su|pw|me|dev|app|co|us|uk|de|fr|nl|br|in|jp|pl|se|no|es|it)\b", re.I)
URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)
REGISTRY = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'|]{3,}", re.I)
WINPATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|*?]{2,}", re.I)
MUTEX = re.compile(r"\\?(?:BaseNamedObjects\\|Global\\|Local\\)[^\s\"']{3,}", re.I)

FILE_ARGUMENTS = (
    "file_name", "filename", "filepath", "file_path", "path", "object_name",
    "target_path", "destination", "source", "buffer", "module_path", "image_path",
)
HOST_ARGUMENTS = ("hostname", "host_name", "server_name", "name", "address", "ip", "ip_address", "server")
URL_ARGUMENTS = ("url", "uri", "object_name", "referer")
REGISTRY_ARGUMENTS = ("regkey", "subkey", "key_handle", "key_name", "registry_key", "keypath", "full_key")
SERVICE_ARGUMENTS = ("service_name", "display_name", "service", "binary_path")

# Values that are part of every Windows run and would drown the real indicators.
BENIGN_PATHS = (
    "c:\\windows\\system32\\kernel32.dll",
    "c:\\windows\\system32\\ntdll.dll",
    "c:\\windows\\system32\\user32.dll",
    "c:\\windows\\system32\\advapi32.dll",
    "c:\\windows\\system32\\msvcrt.dll",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\system32\\windows\\",
    "\\??\\",
    "c:\\users\\admin\\appdata\\local\\temp\\_mei",
)
BENIGN_DOMAINS = (
    "schemas.microsoft.com",
    "windowsupdate.com",
    "microsoft.com",
    "msftconnecttest.com",
    "digicert.com",
    "verisign.com",
    "w3.org",
    "verisign.net",
    "globalsign.com",
    "sectigo.com",
    "time.windows.com",
    "crl.microsoft.com",
    "ocsp.",
)


def _benign(value: str) -> bool:
    low = value.lower()
    if any(marker in low for marker in BENIGN_PATHS):
        return True
    if any(host in low for host in BENIGN_DOMAINS):
        return True
    if low.endswith((".dll", ".sys", ".mui", ".cat", ".nls", ".dat")) and "temp" not in low:
        return True
    if low.startswith(("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")) and low.endswith(".dll"):
        return True
    for noisy in ("\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce",):
        if low.startswith(noisy):
            return False
    return False


class IocCollector:
    """Ordered, de-duplicated IOC collection."""

    TYPE_ORDER = ("url", "ipv4", "domain", "registry", "file", "mutex", "service", "command", "crypto")

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], dict] = {}

    def add(self, ioc_type: str, value: str, source: str, context: str = "", confidence: float | None = None) -> None:
        value = str(value).strip().strip("\"'")
        if not value or len(value) < 3:
            return
        if ioc_type in ("file", "path") and _benign(value):
            return
        if ioc_type == "domain" and _benign(value):
            return
        if ioc_type in ("ipv4", "domain", "url") and value.lower() in ("127.0.0.1", "0.0.0.0", "localhost"):
            return
        value = value.rstrip(".,;:)]}")
        key = (ioc_type, value.lower())
        if key in self._items:
            item = self._items[key]
            if source and source not in item["source"]:
                item["source"] = f"{item['source']}, {source}"
            return
        if confidence is None:
            confidence = {"url": 0.95, "ipv4": 0.9, "domain": 0.8, "registry": 0.85, "file": 0.75,
                          "mutex": 0.8, "service": 0.85, "command": 0.7, "crypto": 0.6}.get(ioc_type, 0.6)
        self._items[key] = {
            "type": ioc_type,
            "value": value,
            "source": source,
            "context": context[:200],
            "confidence": round(confidence, 2),
        }

    def add_text(self, text: str, source: str, context: str = "", *, allow_paths: bool = True) -> None:
        if not text:
            return
        for match in URL.findall(text):
            self.add("url", match, source, context or text[:120])
        for match in IPv4.findall(text):
            self.add("ipv4", match, source, context or text[:120])
        for match in REGISTRY.findall(text):
            self.add("registry", match, source, context or text[:120])
        for match in MUTEX.findall(text):
            self.add("mutex", match, source, context or text[:120])
        if allow_paths:
            for match in WINPATH.findall(text):
                if "://" in match:
                    continue
                self.add("file", match, source, context or text[:120], confidence=0.6)
        for match in DOMAIN.findall(text):
            self.add("domain", match, source, context or text[:120])

    def items(self) -> list[dict]:
        order = {name: index for index, name in enumerate(self.TYPE_ORDER)}
        return sorted(
            self._items.values(),
            key=lambda item: (order.get(item["type"], 99), -item["confidence"], item["value"].lower()),
        )

    def by_type(self) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = {}
        for item in self.items():
            grouped.setdefault(item["type"], []).append(item)
        return grouped

    def counts(self) -> dict[str, int]:
        return {name: len(values) for name, values in self.by_type().items()}

    def __len__(self) -> int:
        return len(self._items)


def extract_from_calls(calls: list[ApiCall]) -> list[dict]:
    collector = IocCollector()
    for call in calls:
        source = f"{call.api} (pid {call.process_id})"
        arguments = call.arguments_text
        if not arguments:
            continue
        context = arguments[:180]

        if call.category == "file":
            _file_arguments(collector, call, source, context)
        elif call.category == "registry":
            _registry_arguments(collector, call, source, context)
        elif call.category == "network":
            _network_arguments(collector, call, source, context)
        elif call.category == "process":
            _process_arguments(collector, call, source, context)
        elif call.category == "sync":
            mutex = call.arg("mutex_name", "name", default="")
            if mutex:
                collector.add("mutex", mutex, source, context)
        elif call.category == "system":
            service = call.arg(*SERVICE_ARGUMENTS, default="")
            if service and "service" in call.api.lower():
                collector.add("service", service, source, context)

        collector.add_text(arguments, source, context)

    return collector.items()


def _file_arguments(collector: IocCollector, call: ApiCall, source: str, context: str) -> None:
    value = call.arg(*FILE_ARGUMENTS, default="")
    if value:
        collector.add("file", value, source, context)
    handle = call.arg("file_handle", "handle", default="")
    if handle and not value:
        collector.add("file", f"handle:{handle}", source, context, confidence=0.4)


def _registry_arguments(collector: IocCollector, call: ApiCall, source: str, context: str) -> None:
    key = call.arg(*REGISTRY_ARGUMENTS, default="")
    if not key:
        return
    collector.add("registry", key, source, context)
    name = call.arg("value_name", "name", default="")
    if name:
        collector.add("registry", f"{key}\\{name}", source, context, confidence=0.95)


def _network_arguments(collector: IocCollector, call: ApiCall, source: str, context: str) -> None:
    url = call.arg(*URL_ARGUMENTS, default="")
    if url.lower().startswith(("http://", "https://", "ftp://")):
        collector.add("url", url, source, context)
        host = urlsplit(url).hostname
        if host:
            collector.add("domain" if not IPv4.fullmatch(host) else "ipv4", host, source, context)
    host = call.arg(*HOST_ARGUMENTS, default="")
    if host and host.lower() not in ("localhost", "127.0.0.1"):
        ioc_type = "ipv4" if IPv4.fullmatch(host) else "domain"
        collector.add(ioc_type, host, source, context)
    address = call.arg("ip_address", "address", "ip", default="")
    if address:
        match = IPv4.search(address)
        if match:
            collector.add("ipv4", match.group(0), source, context, confidence=0.9)
    port = call.arg("port", default="")
    if port and IPv4.search(context):
        collector.add("ipv4", f"{IPv4.search(context).group(0)}:{port}", source, context, confidence=0.7)


def _process_arguments(collector: IocCollector, call: ApiCall, source: str, context: str) -> None:
    command = call.arg("command_line", "cmdline", default="")
    if command:
        collector.add("command", command, source, context)
        collector.add_text(command, source, context)
    application = call.arg("application_name", "file_name", "module_name", default="")
    if application:
        collector.add("file", application, source, context)


def extract_from_summary(summary: dict, calls: list[ApiCall]) -> list[dict]:
    """Fold in the report's own ``behavior.summary`` sections when present."""
    if not summary:
        return extract_from_calls(calls)
    collector = IocCollector()
    for item in extract_from_calls(calls):
        collector.add(item["type"], item["value"], item["source"], item["context"], item["confidence"])

    mapping = {
        "files": "file",
        "keys": "registry",
        "mutexes": "mutex",
        "services": "service",
        "executed_commands": "command",
    }
    for section, ioc_type in mapping.items():
        for value in summary.get(section) or []:
            if isinstance(value, dict):
                for candidate in value.values():
                    if isinstance(candidate, str):
                        collector.add(ioc_type, candidate, f"summary:{section}", "")
            elif isinstance(value, str):
                collector.add(ioc_type, value, f"summary:{section}", "")
    for section in ("hosts", "domains", "dns_servers", "http", "tcp", "udp"):
        for value in summary.get(section) or []:
            if isinstance(value, dict):
                for candidate in value.values():
                    if isinstance(candidate, str):
                        collector.add_text(candidate, f"summary:{section}", "")
            elif isinstance(value, str):
                collector.add_text(value, f"summary:{section}", "")
    return collector.items()


def to_rows(iocs: list[dict]) -> list[list]:
    return [
        [item["type"], item["value"], f"{item.get('confidence', 0):.2f}", item.get("source", ""), item.get("context", "")]
        for item in iocs
    ]
