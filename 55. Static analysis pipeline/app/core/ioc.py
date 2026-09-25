"""IOC compilation from every analysis layer.

Merges hashes, PE artefacts, classified strings and threat-intel results into a
deduplicated, scored indicator set.  Private/internal addresses and benign
placeholder names are filtered out; defanging is available for sharing.
"""
from __future__ import annotations

import ipaddress
import re

CONFIDENCE = {
    "hash": 0.95,
    "threat_intel_family": 0.85,
    "url": 0.60,
    "ipv4": 0.55,
    "domain": 0.55,
    "tor_address": 0.80,
    "bitcoin": 0.75,
    "registry": 0.50,
    "file_path": 0.45,
    "pdb_path": 0.40,
    "mutex": 0.55,
    "user_agent": 0.50,
    "command": 0.45,
    "credential": 0.50,
    "email": 0.40,
}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV4_PORT_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b")

# Strings that look like IOCs but are almost always noise from the toolchain.
_NOISE = re.compile(
    r"(?i)(microsoft\.com|windows\.com|msdn\.com|schemas\.|w3\.org|verisign|digicert|"
    r"globalsign|sectigo|entrust|thawte|symantec|localhost|example\.com|microsoft\.corp|"
    r"\.dll$|\.mui$|kernel32|user32|advapi32|ntdll|msvcrt|\.pdb$)",
)

_STRING_IOC_CLASSES = {
    "url": "url",
    "ipv4": "ipv4",
    "domain": "domain",
    "tor_address": "tor_address",
    "bitcoin": "bitcoin",
    "registry": "registry",
    "file_path": "file_path",
    "pdb_path": "pdb_path",
    "mutex": "mutex",
    "user_agent": "user_agent",
    "command": "command",
    "credential": "credential",
    "email": "email",
    "unc_path": "file_path",
}


def is_noise(value: str) -> bool:
    """True for benign toolchain/OS strings that must not raise suspicion."""
    return bool(_NOISE.search(str(value)))


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except Exception:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def defang(value: str) -> str:
    """Neutralise a URL/IP/domain so it cannot be clicked or resolved."""
    out = str(value)
    out = re.sub(r"(?i)^http:", "hxxp:", out)
    out = re.sub(r"(?i)^https:", "hxxps:", out)
    out = out.replace("://", "[://]")
    out = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", out)
    out = re.sub(r"\.(?=[a-z]{2,})", "[.]", out, flags=re.I)
    out = out.replace("@", "[@]")
    return out


def compile_iocs(
    *,
    hashes: dict | None = None,
    pe_info: dict | None = None,
    string_rows: list[dict] | None = None,
    intel: dict | None = None,
    file_name: str = "",
    include_private: bool = False,
    max_per_type: int = 500,
) -> list[dict]:
    """Return the compiled IOC list, newest findings first per type."""
    hashes = hashes or {}
    pe_info = pe_info or {}
    string_rows = string_rows or []
    intel = intel or {}

    found: dict[tuple[str, str], dict] = {}

    def add(ioc_type: str, value: str, source: str, context: str = "", confidence: float | None = None) -> None:
        value = str(value).strip()
        if not value:
            return
        if ioc_type == "ipv4":
            # ``10.1.2.3:8443`` is stored as the bare address with the port moved
            # into the context so pivots and blocklists stay well formed.
            match = _IPV4_RE.search(value)
            if not match:
                return
            port = _IPV4_PORT_RE.search(value)
            if port:
                context = (context + f" port {port.group(1)}").strip()
            value = match.group()
        if ioc_type == "ipv4" and not include_private and is_private_ip(value):
            return
        if ioc_type in ("url", "domain", "email") and _NOISE.search(value):
            return
        if len(value) > 512:
            value = value[:512]
        key = (ioc_type, value.lower())
        existing = found.get(key)
        conf = CONFIDENCE.get(ioc_type, 0.4) if confidence is None else confidence
        if existing:
            if source not in existing["sources"]:
                existing["sources"].append(source)
            existing["confidence"] = min(1.0, max(existing["confidence"], conf) + 0.1)
            return
        found[key] = {
            "ioc_type": ioc_type,
            "value": value,
            "source": source,
            "sources": [source],
            "confidence": conf,
            "context": context[:220],
        }

    # --------------------------------------------------------------- hashes
    for algo in ("sha256", "sha1", "md5", "imphash"):
        value = hashes.get(algo) or (pe_info.get("imphash") if algo == "imphash" else "")
        if value:
            add("hash", value, "static", f"{algo.upper()} of the analysed file", 0.95)

    # ------------------------------------------------------- PE artefacts
    if pe_info.get("pdb_path"):
        add("pdb_path", pe_info["pdb_path"], "static", "PDB path from the debug directory", 0.45)
    if pe_info.get("imphash"):
        add("hash", pe_info["imphash"], "static", "imphash (import hash)", 0.7)
    if file_name:
        add("file_name", file_name, "static", "Original file name", 0.3)

    # ------------------------------------------------------------- strings
    per_type: dict[str, int] = {}
    for row in string_rows:
        ioc_type = _STRING_IOC_CLASSES.get(row.get("classification", ""))
        if not ioc_type:
            continue
        per_type[ioc_type] = per_type.get(ioc_type, 0) + 1
        if per_type[ioc_type] > max_per_type:
            continue
        add(
            ioc_type,
            row["value"],
            "static",
            f"{row.get('type', 'ascii')} string at offset {row.get('offset_hex', '')}",
        )

    # --------------------------------------------------------------- intel
    for family in intel.get("families", []) or []:
        if family:
            add("malware_family", family, "threat intel", "Reported by threat intel", 0.85)
    for tag in intel.get("tags", []) or []:
        if tag and len(tag) > 2:
            add("tag", tag, "threat intel", "Tag reported by threat intel", 0.4)
    if intel.get("detection_ratio"):
        add(
            "detection_ratio",
            intel["detection_ratio"],
            "threat intel",
            "Multi-engine detection ratio",
            0.8,
        )

    order = {
        "url": 0, "domain": 1, "ipv4": 2, "tor_address": 3, "bitcoin": 4,
        "registry": 5, "mutex": 6, "file_path": 7, "user_agent": 8, "command": 9,
        "credential": 10, "email": 11, "pdb_path": 12, "hash": 13,
        "malware_family": 14, "detection_ratio": 15, "tag": 16, "file_name": 17,
    }
    rows = list(found.values())
    for row in rows:
        row["value"] = row["value"]
        row["sources"] = ", ".join(row["sources"])
    rows.sort(key=lambda r: (order.get(r["ioc_type"], 99), -r["confidence"], r["value"]))
    return rows


def ioc_stats(iocs: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc["ioc_type"]] = counts.get(ioc["ioc_type"], 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def defang_rows(iocs: list[dict]) -> list[list]:
    """IOC rows in a sharing-safe (defanged) form for CSV/HTML exports."""
    rows = []
    for ioc in iocs:
        value = ioc["value"]
        if ioc["ioc_type"] in ("url", "domain", "ipv4", "tor_address", "email"):
            value = defang(value)
        rows.append(
            [
                ioc["ioc_type"],
                value,
                ioc.get("sources", ioc.get("source", "")),
                f"{float(ioc.get('confidence', 0)):.2f}",
                ioc.get("context", ""),
            ]
        )
    return rows
