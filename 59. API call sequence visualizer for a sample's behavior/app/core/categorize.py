"""API categorisation (architecture §3.5).

Cuckoo and CAPE already tag most calls with a category, and that tag is trusted
first.  When it is missing — hand-written logs, trimmed reports, a few CAPE
builds — the API name is classified by prefix and by known-function lists, which
is what the architecture's fallback rule describes.
"""
from __future__ import annotations

CATEGORIES = (
    "process",
    "memory",
    "file",
    "registry",
    "network",
    "sync",
    "system",
    "ui",
    "crypto",
    "other",
)

CATEGORY_COLORS = {
    "process": "#e5484d",
    "memory": "#f5a524",
    "file": "#30a46c",
    "registry": "#a855f7",
    "network": "#4da3ff",
    "sync": "#8b8d98",
    "system": "#b08968",
    "ui": "#22d3ee",
    "crypto": "#c4319a",
    "other": "#6b7687",
}

# Normalises the labels CAPE/Cuckoo use for the same idea.
ALIASES = {
    "registry": "registry",
    "reg": "registry",
    "file": "file",
    "filesystem": "file",
    "network": "network",
    "net": "network",
    "socket": "network",
    "process": "process",
    "proc": "process",
    "thread": "process",
    "memory": "memory",
    "mem": "memory",
    "sync": "sync",
    "synchronization": "sync",
    "mutex": "sync",
    "system": "system",
    "services": "system",
    "service": "system",
    "ui": "ui",
    "gui": "ui",
    "crypto": "crypto",
    "cryptography": "crypto",
    "certificate": "crypto",
    "device": "system",
    "driver": "system",
    "hook": "system",
    "com": "system",
    "ole": "system",
    "browser": "file",
    "iexplore": "network",
    "browser_features": "file",
}

PREFIX_RULES: list[tuple[tuple[str, ...], str]] = [
    (("reg", "ntopenkey", "ntsetvalue", "ntqueryvalue"), "registry"),
    (
        (
            "createfile",
            "readfile",
            "writefile",
            "deletefile",
            "copyfile",
            "movefile",
            "findfirstfile",
            "findnextfile",
            "getfileattributes",
            "setfileattributes",
            "getfilesize",
            "setendoffile",
            "gettemp path",
            "gettemppath",
            "getfullpathname",
            "createmapping",
            "ntcreatefile",
            "ntreadfile",
            "ntwritefile",
            "findfirstfileex",
            "remove directory",
            "removedirectory",
            "createdirectory",
        ),
        "file",
    ),
    (
        (
            "internet",
            "winhttp",
            "winnet",
            "http",
            "https",
            "socket",
            "connect",
            "send",
            "recv",
            "wsastartup",
            "gethostbyname",
            "dnsquery",
            "urldownload",
            "ftp",
            "smtp",
            "urlmon",
        ),
        "network",
    ),
    (
        (
            "virtualalloc",
            "virtualprotect",
            "virtualfree",
            "heapalloc",
            "heapfree",
            "rtlmovememory",
            "ntallocatevirtualmemory",
            "ntprotectvirtualmemory",
            "writeprocessmemory",
            "readprocessmemory",
            "mapviewoffile",
            "unmapviewoffile",
            "localalloc",
            "globalalloc",
        ),
        "memory",
    ),
    (
        (
            "createprocess",
            "shellexecute",
            "winexec",
            "createRemoteThread",
            "createthread",
            "openprocess",
            "terminateprocess",
            "resumethread",
            "suspendthread",
            "setthreadcontext",
            "getthreadcontext",
            "queueuserapc",
            "ntcreatethreadex",
            "ntmapviewofsection",
            "process32",
            "thread32",
            "enumprocesses",
            "isdebuggerpresent",
            "debugactiveprocess",
            "ntsetinformationprocess",
        ),
        "process",
    ),
    (("mutex", "waitforsingleobject", "createevent", "setevent", "criticalsection", "semaphore"), "sync"),
    (("crypt", "bcrypt", "ncrypt", "certopen", "cert", "advapi"), "crypto"),
    (("messagebox", "getforegroundwindow", "createwindow", "wsprintf", "setwindow", "findwindow"), "ui"),
    (("getsysteminfo", "getcomputername", "getusername", "getvolumeinformation", "ntquery", "time", "sleepex"), "system"),
]

SUSPICIOUS_APIS = {
    "virtualallocex": "remote memory allocation (injection precursor)",
    "writeprocessmemory": "writes into another process (injection)",
    "createremotethread": "remote thread creation (injection)",
    "ntmapviewofsection": "section mapping into another process",
    "queueuserapc": "APC injection",
    "setwindowshookex": "global hooking",
    "process32first": "process enumeration",
    "isdebuggerpresent": "anti-debug check",
    "checkremotedebuggerpresent": "anti-debug check",
    "outputdebugstring": "anti-debug trick",
    "getsystemfirmwaretable": "environment fingerprinting",
    "readprocessmemory": "reads another process (credential access when aimed at lsass)",
    "openprocess": "opens another process handle",
    "createservice": "service creation (persistence / privilege)",
    "regsetvalueex": "registry write",
    "regsetvalue": "registry write",
    "internetopen": "network stack initialisation",
    "httpsendrequest": "HTTP request",
    "shellexecute": "shell execution",
    "winexec": "process execution",
    "powershell": "script execution",
    "cryptencrypt": "encryption (ransomware behaviour)",
    "cryptgenkey": "key generation",
    "deletefile": "file deletion",
    "movefileex": "file move / deletion on reboot",
    "findfirstfile": "file enumeration",
}


def normalise(category: str | None, api: str) -> str:
    """Return the canonical category for one call."""
    label = (category or "").strip().lower().replace(" ", "_")
    if label in ALIASES:
        return ALIASES[label]
    if label in CATEGORIES:
        return label
    return classify(api)


def classify(api: str) -> str:
    """Heuristic classification by API name."""
    name = (api or "").lower().replace("!", "").replace("::", "").strip()
    if not name:
        return "other"
    for prefixes, category in PREFIX_RULES:
        if name.startswith(prefixes):
            return category
    for prefixes, category in PREFIX_RULES:
        if any(prefix in name for prefix in prefixes):
            return category
    return "other"


def color_for(category: str) -> str:
    return CATEGORY_COLORS.get(category, CATEGORY_COLORS["other"])


def is_suspicious(api: str) -> str:
    """Return the suspicion note for an API name, or an empty string."""
    name = (api or "").lower()
    if name in SUSPICIOUS_APIS:
        return SUSPICIOUS_APIS[name]
    for key, note in SUSPICIOUS_APIS.items():
        if key in name:
            return note
    return ""
