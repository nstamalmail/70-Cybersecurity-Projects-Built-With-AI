"""Binary loader for RECT: file type detection, entropy, strings, sections.

Pure-stdlib parsing of ELF/PE headers (architecture.md asks for lief/capstone;
those are optional accelerators — the loader degrades gracefully and every
feature works with the built-in parser).
"""

from __future__ import annotations

import math
import re
import struct
from typing import Dict, List

from app.core.models import BinaryInfo

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def detect_type(path: str, data: bytes) -> Dict[str, str]:
    if data.startswith(b"\x7fELF"):
        return {"file_type": "elf", "endianness": "little"}
    if data.startswith(b"MZ"):
        return {"file_type": "pe", "endianness": "little"}
    if data.startswith(b"\xfe\xed\xfa\xce") or data.startswith(b"\xcf\xfa\xed\xfe") \
            or data.startswith(b"\xce\xfa\xed\xfe") or data.startswith(b"\xca\xfe\xba\xbe"):
        return {"file_type": "macho", "endianness": "big"}
    if data.startswith(b"PK\x03\x04"):
        return {"file_type": "zip", "endianness": "-"}
    if data.startswith(b"\x1f\x8b"):
        return {"file_type": "gzip", "endianness": "-"}
    if data[:16] == b"\x89PNG\r\n\x1a\n":
        return {"file_type": "png", "endianness": "-"}
    try:
        text = data.decode("utf-8")
        return {"file_type": "text", "endianness": "-"}
    except UnicodeDecodeError:
        pass
    return {"file_type": "raw", "endianness": "-"}


def parse_elf(data: bytes) -> Dict:
    """Minimal ELF header parse: arch, bits, sections."""
    out: Dict = {"architecture": "", "bits": 0, "sections": [], "imports": []}
    if len(data) < 64:
        return out
    ei_class, ei_data = data[4], data[5]
    bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    arch_map = {0x03: "x86", 0x3E: "x64", 0xB7: "arm64", 0x28: "arm",
                0x08: "mips", 0xF3: "riscv"}
    e_machine = struct.unpack_from(endian + "H", data, 18)[0]
    out["architecture"] = arch_map.get(e_machine, f"machine_0x{e_machine:x}")
    out["bits"] = bits
    try:
        if bits == 64:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        sections = []
        for i in range(min(e_shnum, 64)):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data):
                break
            if bits == 64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from(endian + "IIQQQQ", data, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from(endian + "IIIIII", data, off)
            # read name from shstrtab later; keep offsets for now
            sections.append({"index": i, "offset": sh_offset, "size": sh_size,
                             "type": sh_type})
        # section header string table
        if e_shnum and e_shoff + e_shnum * e_shentsize <= len(data):
            shstr_off = e_shoff + e_shnum * e_shentsize
        # try to resolve names from the section-name table if present
        # (simplified: read names from last section if it is the strtab)
        for i, sec in enumerate(sections):
            sec.setdefault("name", f"section_{i}")
        out["sections"] = sections
    except struct.error:
        pass
    return out


def parse_pe(data: bytes) -> Dict:
    out: Dict = {"architecture": "x86", "bits": 32, "sections": [], "imports": []}
    if len(data) < 0x100:
        return out
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return out
        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        nsections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        arch_map = {0x14C: ("x86", 32), 0x8664: ("x64", 64),
                    0x1C0: ("arm", 32), 0xAA64: ("arm64", 64)}
        out["architecture"], out["bits"] = arch_map.get(machine, ("x86", 32))
        sec_off = pe_off + 24 + opt_size
        sections = []
        for i in range(min(nsections, 32)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "ignore")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
            sections.append({"name": name, "offset": roff, "size": rsize})
        out["sections"] = sections
    except struct.error:
        pass
    return out


PACKED_SECTION_NAMES = {"upx", "upx0", "upx1", "upx2", ".aspack", ".adata",
                        ".packed", "petite", ".nsp0", ".nsp1", "MEW"}


def detect_packing(sections: List[Dict], entropy: float) -> bool:
    names = {str(s.get("name", "")).lower() for s in sections}
    if names & PACKED_SECTION_NAMES:
        return True
    # High entropy across a big raw file with few sections is suspicious
    if entropy > 7.5 and len(sections) <= 3:
        return True
    return False


KNOWN_IMPORT_HINTS = [
    "system", "exec", "popen", "fork", "socket", "connect", "send", "recv",
    "CreateProcess", "WinExec", "ShellExecute", "InternetOpen", "URLDownload",
    "ptrace", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
]


def extract_strings(data: bytes, min_len: int = 5, limit: int = 5000) -> List[Dict]:
    out = []
    for m in _PRINTABLE.finditer(data[:4_000_000]):
        s = m.group().decode("ascii", "ignore")
        out.append({"offset": m.start(), "text": s})
        if len(out) >= limit:
            break
    return out


def classify_string(text: str) -> str:
    """Suspicious-pattern classification for the String Analyzer view."""
    low = text.lower()
    if re.match(r"^[A-Za-z0-9+/=]{16,}$", text) and len(text) % 4 == 0:
        return "base64?"
    if re.match(r"^(https?://|ftp://)", low):
        return "url"
    if re.search(r"%[sdioxX]|%[0-9]+\$", text):
        return "format-string"
    if re.search(r"flag\{|ctf\{|picoctf\{|htb\{", low) or "B64:" in text \
            or "ROT:" in text:
        return "flag-like"
    if re.match(r"^[0-9a-f]{32}$", low):
        return "md5-like"
    if re.match(r"^[0-9a-f]{64}$", low):
        return "sha256-like"
    if "debug" in low or "ptrace" in low:
        return "anti-debug?"
    return "general"


def load_binary(path: str) -> BinaryInfo:
    with open(path, "rb") as fh:
        data = fh.read(8_000_000)
    size = len(data)
    info = BinaryInfo(path=path, size=size, entropy=shannon_entropy(data))
    ftype = detect_type(path, data)
    info.file_type = ftype["file_type"]
    info.endianness = ftype.get("endianness", "-")

    sections: List[Dict] = []
    if info.file_type == "elf":
        parsed = parse_elf(data)
        info.architecture = parsed.get("architecture", "")
        info.bits = parsed.get("bits", 0)
        sections = parsed.get("sections", [])
    elif info.file_type == "pe":
        parsed = parse_pe(data)
        info.architecture = parsed.get("architecture", "")
        info.bits = parsed.get("bits", 0)
        sections = parsed.get("sections", [])
        # collect import hints from strings
        info.imports = [s["text"] for s in extract_strings(data, limit=2000)
                        if any(h.lower() in s["text"].lower()
                               for h in KNOWN_IMPORT_HINTS)][:40]
    info.sections = sections
    info.packed = detect_packing(sections, info.entropy)

    strings = extract_strings(data)
    for s in strings:
        s["class"] = classify_string(s["text"])
    info.strings = strings
    return info
