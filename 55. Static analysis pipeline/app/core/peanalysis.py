"""PE parsing layer (``pefile`` based).

Extracts headers, sections with Shannon entropy, the import/export tables, the
debug (PDB) path and the resource summary, then derives anomalies and
capability groupings that feed the verdict engine.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from app.core.hashing import entropy, human_size

# API -> (capability, weight, note).  Weight feeds the verdict engine.
SUSPICIOUS_IMPORTS: dict[str, tuple[str, int, str]] = {
    # process injection
    "createremotethread": ("process injection", 12, "Classic remote thread injection"),
    "createremotethreadex": ("process injection", 12, "Remote thread injection"),
    "ntcreatethreadex": ("process injection", 12, "Native remote thread injection"),
    "virtualallocex": ("process injection", 10, "Remote memory allocation"),
    "writeprocessmemory": ("process injection", 12, "Writes into another process"),
    "readprocessmemory": ("credential access", 10, "Reads another process memory (lsass?)"),
    "openprocess": ("process injection", 5, "Opens a handle to another process"),
    "queueuserapc": ("process injection", 10, "APC injection"),
    "setthreadcontext": ("process injection", 10, "Hijacks a thread via context swap"),
    "createtoolhelp32snapshot": ("discovery", 4, "Process/thread enumeration"),
    "process32first": ("discovery", 3, "Process enumeration"),
    "process32next": ("discovery", 3, "Process enumeration"),
    "isdebuggerpresent": ("anti-analysis", 6, "Debugger check"),
    "checkremotedebuggerpresent": ("anti-analysis", 6, "Debugger check"),
    "ntqueryinformationprocess": ("anti-analysis", 4, "Native process information query"),
    "getsysteminfo": ("anti-analysis", 2, "Environment fingerprinting"),
    "globalmemorystatusex": ("anti-analysis", 2, "Environment fingerprinting"),
    # persistence
    "regsetvalueexw": ("persistence", 8, "Registry write (Run keys / services)"),
    "regsetvalueexa": ("persistence", 8, "Registry write (Run keys / services)"),
    "regcreatekeyexw": ("persistence", 5, "Registry key creation"),
    "createservicew": ("persistence", 12, "Service installation"),
    "createservicea": ("persistence", 12, "Service installation"),
    "changeserviceconfigw": ("persistence", 10, "Service reconfiguration"),
    "schtasks": ("persistence", 10, "Scheduled task creation"),
    # network
    "internetopen": ("network", 6, "WinINet session"),
    "internetopenurl": ("network", 8, "WinINet URL fetch"),
    "internetconnect": ("network", 8, "WinINet connection"),
    "httpsendrequest": ("network", 8, "HTTP request"),
    "internetreadfile": ("network", 6, "HTTP response read"),
    "urldownloadtofile": ("network", 12, "Downloads a file from a URL"),
    "wsastartup": ("network", 4, "Winsock initialisation"),
    "socket": ("network", 4, "Raw socket"),
    "connect": ("network", 4, "Raw outbound connection"),
    "send": ("network", 3, "Raw socket send"),
    "recv": ("network", 3, "Raw socket receive"),
    "winhttpopen": ("network", 6, "WinHTTP session"),
    "winhttpconnect": ("network", 8, "WinHTTP connection"),
    # crypto / ransomware
    "cryptencrypt": ("crypto", 10, "Encryption primitive"),
    "cryptdecrypt": ("crypto", 8, "Decryption primitive"),
    "cryptgenkey": ("crypto", 8, "Symmetric key generation"),
    "cryptacquirecontextw": ("crypto", 6, "Crypto context"),
    "bcryptencrypt": ("crypto", 10, "CNG encryption primitive"),
    # evasion / execution
    "winexec": ("execution", 8, "Legacy process execution"),
    "shellexecutea": ("execution", 6, "Shell execution"),
    "shellexecutew": ("execution", 6, "Shell execution"),
    "createprocessa": ("execution", 5, "Process creation"),
    "createprocessw": ("execution", 5, "Process creation"),
    "loadlibrarya": ("execution", 4, "Runtime library load (possible reflective load)"),
    "getprocaddress": ("execution", 4, "Dynamic API resolution (hiding imports)"),
    "virtualprotect": ("evasion", 6, "Memory permission change (unpacking)"),
    "ntunmapviewofsection": ("evasion", 10, "Section unmapping (hollowing)"),
    "zwunmapviewofsection": ("evasion", 10, "Section unmapping (hollowing)"),
    "settimer": ("evasion", 2, "Timing / sandbox evasion"),
    "sleepex": ("evasion", 8, "Long sleep (sandbox evasion)"),
}

CAPABILITY_ORDER = [
    "process injection",
    "credential access",
    "persistence",
    "network",
    "crypto",
    "execution",
    "evasion",
    "anti-analysis",
    "discovery",
]

_PACKER_SECTION_HINTS = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".upx": "UPX",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".themida": "Themida",
    ".winlice": "Themida",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".packed": "generic packer",
    "petite": "Petite",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
    "upx!": "UPX",
    ".nsp0": "NsPack",
    ".boom": "Themida",
    ".pdata": None,
}


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def parse_pe(path: str | Path | None = None, data: bytes | None = None) -> dict:
    """Parse a PE image into a plain dict (JSON friendly).

    Pass ``data`` whenever the bytes are already in memory: ``pefile`` opens the
    path itself otherwise, which is fragile for paths holding non-UTF-8 bytes
    (common in forensic images and archives).  ``path`` is still used for the
    reported file size and for provenance only.
    """
    import pefile

    p = Path(path) if path else None
    if data is not None:
        pe = pefile.PE(data=data, fast_load=False)
        file_size = len(data)
    elif p is not None:
        file_size = p.stat().st_size
        with p.open("rb") as fh:
            pe = pefile.PE(data=fh.read(), fast_load=False)
    else:
        raise ValueError("parse_pe requires either a path or data")

    info: dict = {"is_pe": True, "path": str(p) if p else "(buffer)"}

    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    machine = int(fh.Machine)
    info["machine"] = {
        0x14C: "x86 (i386)",
        0x8664: "x64 (AMD64)",
        0x1C0: "ARM",
        0xAA64: "ARM64",
        0x200: "IA64",
    }.get(machine, f"0x{machine:04x}")
    info["machine_raw"] = f"0x{machine:04x}"

    ts = int(fh.TimeDateStamp)
    info["timestamp_raw"] = ts
    info["timestamp"] = (
        _dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        if 0 < ts < 0xFFFFFFFF
        else "n/a"
    )
    info["characteristics"] = _characteristics(int(fh.Characteristics), pe)
    info["is_dll"] = bool(fh.Characteristics & 0x2000)
    info["entry_point"] = int(oh.AddressOfEntryPoint)
    info["image_base"] = int(oh.ImageBase)
    info["subsystem"] = {
        1: "Native (driver)",
        2: "Windows GUI",
        3: "Windows console",
        7: "POSIX console",
        9: "Windows CE",
        10: "EFI application",
    }.get(int(oh.Subsystem), f"unknown ({oh.Subsystem})")
    info["dll_characteristics"] = _dll_characteristics(int(oh.DllCharacteristics))
    info["size_of_image"] = int(oh.SizeOfImage)
    info["size_of_headers"] = int(oh.SizeOfHeaders)
    info["linker"] = f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"
    info["os_version"] = f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}"
    info["checksum"] = int(oh.CheckSum)
    overlay_off = _safe(lambda: pe.get_overlay_data_start_offset(), None)
    info["overlay_offset"] = int(overlay_off) if overlay_off else 0
    info["overlay_size"] = (
        max(0, file_size - int(overlay_off)) if overlay_off else 0
    )
    info["file_size"] = file_size

    # ------------------------------------------------------------- sections
    sections = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("latin-1", "replace")
        data = _safe(sec.get_data, b"") or b""
        sec_entropy = entropy(data) if data else 0.0
        sections.append(
            {
                "name": name,
                "virtual_address": int(sec.VirtualAddress),
                "virtual_size": int(sec.Misc_VirtualSize),
                "raw_size": int(sec.SizeOfRawData),
                "raw_pointer": int(sec.PointerToRawData),
                "entropy": sec_entropy,
                "entropy_str": f"{sec_entropy:.2f}",
                "characteristics": _section_chars(int(sec.Characteristics)),
                "flags": _section_perms(int(sec.Characteristics)),
                "wx": _is_wx(int(sec.Characteristics)),
                "executable": bool(int(sec.Characteristics) & 0x20000000),
                "size_str": human_size(int(sec.SizeOfRawData)),
                "packer": _PACKER_SECTION_HINTS.get(name.lower().strip()),
                "md5": _safe(lambda: sec.get_hash_md5(), ""),
            }
        )
    info["sections"] = sections
    info["section_count"] = len(sections)

    # -------------------------------------------------------------- imports
    imports: dict[str, list[str]] = {}
    for entry in _safe(lambda: pe.DIRECTORY_ENTRY_IMPORT, []) or []:
        dll = entry.dll.decode("latin-1", "replace")
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("latin-1", "replace"))
            elif imp.ordinal is not None:
                funcs.append(f"#{imp.ordinal}")
        imports[dll] = funcs
    info["imports"] = imports
    info["import_count"] = sum(len(v) for v in imports.values())
    info["imphash"] = _safe(lambda: pe.get_imphash(), "")

    # -------------------------------------------------------------- exports
    exports = []
    for sym in _safe(lambda: pe.DIRECTORY_ENTRY_EXPORT.symbols, []) or []:
        exports.append(
            sym.name.decode("latin-1", "replace")
            if sym.name
            else f"ordinal {sym.ordinal}"
        )
    info["exports"] = exports

    # ---------------------------------------------------------------- debug
    pdb_path = None
    debug_entries = []
    for dbg in _safe(lambda: pe.DIRECTORY_ENTRY_DEBUG, []) or []:
        entry = _safe(lambda: dbg.entry)
        raw = _safe(lambda: entry.PdbFileName, b"") or b""
        pdb = raw.rstrip(b"\x00").decode("latin-1", "replace") if raw else None
        if pdb:
            pdb_path = pdb
        debug_entries.append(
            {
                "type": _debug_type(int(_safe(lambda: entry.struct.Type, 0) or 0)),
                "timestamp": _safe(lambda: str(entry.TimeDateStamp), ""),
                "pdb": pdb or "",
                "size": int(_safe(lambda: entry.struct.SizeOfData, 0) or 0),
            }
        )
    info["debug_entries"] = debug_entries
    info["pdb_path"] = pdb_path

    # ------------------------------------------------------------ resources
    resources: list[dict] = []
    for rtype in _safe(lambda: pe.DIRECTORY_ENTRY_RESOURCE.entries, []) or []:
        type_name = _resource_type(int(rtype.id)) if rtype.id is not None else str(rtype.name)
        count = len(_safe(lambda: rtype.directory.entries, []) or [])
        resources.append({"type": type_name, "count": count})
    info["resources"] = resources

    info["has_rich_header"] = bool(_safe(lambda: pe.RICH_HEADER, None))
    info["has_tls"] = bool(_safe(lambda: pe.DIRECTORY_ENTRY_TLS, None))
    info["load_config"] = bool(_safe(lambda: pe.DIRECTORY_ENTRY_LOAD_CONFIG, None))
    info["entry_section"] = _section_for_rva(sections, info["entry_point"])

    pe.close()
    return info


def _section_for_rva(sections: list[dict], rva: int) -> str:
    for sec in sections:
        start = sec["virtual_address"]
        size = max(sec["virtual_size"], sec["raw_size"])
        if start <= rva < start + max(size, 1):
            return sec["name"]
    return "(outside all sections)"


def _is_wx(chars: int) -> bool:
    return bool(chars & 0x20000000) and bool(chars & 0x80000000)


def _section_perms(chars: int) -> str:
    return (
        ("R" if chars & 0x40000000 else "-")
        + ("W" if chars & 0x80000000 else "-")
        + ("X" if chars & 0x20000000 else "-")
    )


def _section_chars(chars: int) -> str:
    names = []
    if chars & 0x00000020:
        names.append("CNT_CODE")
    if chars & 0x00000040:
        names.append("CNT_INITIALIZED_DATA")
    if chars & 0x00000080:
        names.append("CNT_UNINITIALIZED_DATA")
    if chars & 0x02000000:
        names.append("MEM_DISCARDABLE")
    if chars & 0x10000000:
        names.append("MEM_SHARED")
    if chars & 0x20000000:
        names.append("MEM_EXECUTE")
    if chars & 0x40000000:
        names.append("MEM_READ")
    if chars & 0x80000000:
        names.append("MEM_WRITE")
    return " | ".join(names)


def _characteristics(chars: int, pe) -> str:
    names = []
    if chars & 0x0002:
        names.append("EXECUTABLE_IMAGE")
    if chars & 0x0020:
        names.append("LARGE_ADDRESS_AWARE")
    if chars & 0x0100:
        names.append("32BIT_MACHINE")
    if chars & 0x2000:
        names.append("DLL")
    if chars & 0x0001:
        names.append("RELOCS_STRIPPED")
    if chars & 0x0004:
        names.append("LINE_NUMS_STRIPPED")
    if chars & 0x0008:
        names.append("LOCAL_SYMS_STRIPPED")
    return " | ".join(names) or "(none)"


def _dll_characteristics(chars: int) -> str:
    names = []
    mapping = [
        (0x0020, "HIGH_ENTROPY_VA"),
        (0x0040, "DYNAMIC_BASE (ASLR)"),
        (0x0080, "FORCE_INTEGRITY"),
        (0x0100, "NX_COMPAT (DEP)"),
        (0x0200, "NO_ISOLATION"),
        (0x0400, "NO_SEH"),
        (0x0800, "NO_BIND"),
        (0x4000, "GUARD_CF (CFG)"),
        (0x8000, "TERMINAL_SERVER_AWARE"),
    ]
    for bit, label in mapping:
        if chars & bit:
            names.append(label)
    return " | ".join(names) or "(none)"


def _debug_type(value: int) -> str:
    return {
        0: "UNKNOWN",
        1: "COFF",
        2: "CODEVIEW",
        3: "FPO",
        4: "MISC",
        5: "EXCEPTION",
        9: "BORLAND",
        12: "VC_FEATURE",
        16: "REPRO",
    }.get(value, str(value))


def _resource_type(value: int) -> str:
    return {
        1: "CURSOR",
        2: "BITMAP",
        3: "ICON",
        4: "MENU",
        5: "DIALOG",
        6: "STRING",
        10: "RCDATA",
        14: "GROUP_ICON",
        16: "VERSION",
        24: "MANIFEST",
    }.get(value, f"type {value}")


# --------------------------------------------------------------------------- #
#  Derivation: capabilities, anomalies, packer hints
# --------------------------------------------------------------------------- #
def capability_hits(pe_info: dict) -> list[dict]:
    """Match imported APIs against the suspicious-API capability table."""
    hits: list[dict] = []
    for dll, funcs in (pe_info.get("imports") or {}).items():
        for func in funcs:
            key = func.lower()
            entry = SUSPICIOUS_IMPORTS.get(key)
            if not entry:
                continue
            capability, weight, note = entry
            hits.append(
                {
                    "api": func,
                    "dll": dll,
                    "capability": capability,
                    "weight": weight,
                    "note": note,
                }
            )
    hits.sort(key=lambda h: (-h["weight"], h["capability"]))
    return hits


def capability_summary(hits: list[dict]) -> list[tuple[str, int, int]]:
    """(capability, api_count, worst_weight) grouped and ordered for display."""
    grouped: dict[str, list[dict]] = {}
    for hit in hits:
        grouped.setdefault(hit["capability"], []).append(hit)
    rows = []
    for capability, items in sorted(
        grouped.items(),
        key=lambda kv: (CAPABILITY_ORDER.index(kv[0]) if kv[0] in CAPABILITY_ORDER else 99, -len(kv[1])),
    ):
        rows.append(
            (
                capability,
                len(items),
                max(i["weight"] for i in items),
            )
        )
    return rows


def detect_anomalies(pe_info: dict, file_size: int | None = None) -> list[dict]:
    """Structural anomalies, each with a severity used by the verdict engine."""
    out: list[dict] = []
    sections = pe_info.get("sections") or []

    highest = 0.0
    worst_section = ""
    for sec in sections:
        if sec["raw_size"] > 0 and sec["entropy"] > highest:
            highest = sec["entropy"]
            worst_section = sec["name"]

    for sec in sections:
        if sec["raw_size"] > 0 and sec["entropy"] > 7.0:
            out.append(
                {
                    "id": "high-entropy-section",
                    "severity": "medium",
                    "title": f"High entropy section {sec['name']} ({sec['entropy']:.2f})",
                    "detail": "Entropy above 7.0 suggests packed or encrypted content.",
                }
            )
        if sec["wx"]:
            out.append(
                {
                    "id": "wx-section",
                    "severity": "high",
                    "title": f"Writable + executable section {sec['name']}",
                    "detail": "W+X memory is typical of packers, shellcode loaders and injection stubs.",
                }
            )
        if sec["name"] and not sec["name"].startswith(".") and sec["name"].lower() not in ("upx0", "upx1"):
            out.append(
                {
                    "id": "nonstandard-section-name",
                    "severity": "low",
                    "title": f"Non-standard section name '{sec['name']}'",
                    "detail": "Sections outside the usual .text/.rdata/.data/.rsrc set are worth review.",
                }
            )
        if sec["packer"]:
            out.append(
                {
                    "id": "packer-section",
                    "severity": "medium",
                    "title": f"Packer signature in section name '{sec['name']}' \u2192 {sec['packer']}",
                    "detail": "Section naming matches a known executable packer.",
                }
            )

    ep_section = pe_info.get("entry_section") or ""
    if ep_section and ep_section != ".text":
        severity = "medium" if ep_section else "low"
        out.append(
            {
                "id": "entrypoint-outside-text",
                "severity": severity,
                "title": f"Entry point outside .text (in {ep_section})",
                "detail": "Common in packed binaries where the stub runs before the original entry point.",
            }
        )
    if sections and ep_section == sections[-1]["name"] and len(sections) > 1:
        out.append(
            {
                "id": "entrypoint-last-section",
                "severity": "medium",
                "title": "Entry point in the last section",
                "detail": "Typical of packer stubs appended after the original sections.",
            }
        )

    ts = pe_info.get("timestamp_raw") or 0
    if ts:
        try:
            when = _dt.datetime.utcfromtimestamp(ts)
            now = _dt.datetime.utcnow()
            if when > now:
                out.append(
                    {
                        "id": "future-timestamp",
                        "severity": "medium",
                        "title": f"Compile timestamp is in the future ({when:%Y-%m-%d})",
                        "detail": "Timestomping or a forged build date.",
                    }
                )
            elif when.year < 2000:
                out.append(
                    {
                        "id": "implausible-timestamp",
                        "severity": "low",
                        "title": f"Implausible compile timestamp ({when:%Y-%m-%d})",
                        "detail": "Deliberately altered or default-zeroed build time.",
                    }
                )
        except Exception:
            pass

    imports = pe_info.get("imports") or {}
    total_imports = sum(len(v) for v in imports.values())
    if sections and total_imports <= 6:
        out.append(
            {
                "id": "minimal-imports",
                "severity": "medium",
                "title": f"Minimal import table ({total_imports} functions)",
                "detail": "Packed binaries usually resolve most APIs dynamically.",
            }
        )

    if not pe_info.get("debug_entries"):
        out.append(
            {
                "id": "no-debug-directory",
                "severity": "low",
                "title": "No debug directory / PDB path",
                "detail": "Production builds normally strip symbols; combined with other flags this is mildly suspicious.",
            }
        )
    if not pe_info.get("dll_characteristics") or "NX_COMPAT" not in (
        pe_info.get("dll_characteristics") or ""
    ):
        out.append(
            {
                "id": "no-dep",
                "severity": "low",
                "title": "DEP (NX_COMPAT) not enabled",
                "detail": "Missing modern exploit mitigations.",
            }
        )
    if file_size and pe_info.get("overlay_size") and pe_info["overlay_size"] > file_size * 0.25:
        out.append(
            {
                "id": "large-overlay",
                "severity": "medium",
                "title": f"Large overlay ({human_size(pe_info['overlay_size'])})",
                "detail": "Data appended after the last section often carries a second stage.",
            }
        )
    if not pe_info.get("is_dll") and not pe_info.get("exports"):
        pass  # normal for executables
    if pe_info.get("is_dll") and not pe_info.get("exports"):
        out.append(
            {
                "id": "dll-without-exports",
                "severity": "low",
                "title": "DLL with no exports",
                "detail": "A DLL that exports nothing is usually a loader or side-loading target.",
            }
        )
    if highest > 7.2 and worst_section:
        out.append(
            {
                "id": "packing-entropy",
                "severity": "medium",
                "title": f"Packing suspicion: {worst_section} entropy {highest:.2f}",
                "detail": "Entropy above 7.2 across a section indicates compression or encryption.",
            }
        )
    return out


def packer_hints(pe_info: dict) -> list[str]:
    hints = []
    for sec in pe_info.get("sections") or []:
        if sec.get("packer") and sec["packer"] not in hints:
            hints.append(sec["packer"])
    return hints
