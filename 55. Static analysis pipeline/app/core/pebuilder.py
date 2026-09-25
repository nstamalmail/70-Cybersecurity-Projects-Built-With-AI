"""Synthetic PE generator used by the demo fixtures.

The generated files are **inert data blobs** - valid PE headers plus strings.
They contain no executable code and are never run: they exist purely so the
pipeline has something realistic to parse (a packed-looking sample and a benign
release build) without shipping any real malware.
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

TEXT_RVA, TEXT_SIZE = 0x1000, 0x600
RDATA_RVA, RDATA_SIZE = 0x2000, 0x600
DATA_RVA, DATA_SIZE = 0x3000, 0x400
LAST_RVA, LAST_SIZE = 0x4000, 0x600

TEXT_RAW, RDATA_RAW, DATA_RAW, LAST_RAW = 0x400, 0xA00, 0x1000, 0x1400
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
SIZE_OF_IMAGE = 0x5000
# Headers must hold the DOS stub, PE sig, COFF + optional header (0x178) and the
# 4 x 40 byte section table (ends 0x218), so 0x400 with file alignment 0x200.
SIZE_OF_HEADERS = 0x400
SECTION_TABLE_OFFSET = 0x178

PACKED_STRINGS = [
    "http://c2.demo-lab.example/gate.php",
    "https://cdn-update.demo-lab.example/panel/fb.png",
    "185.220.101.44:8443",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "cmd.exe /c vssadmin delete shadows /all /quiet",
    "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
    "Global\\Mutex_demo_9f2a",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BeaconClient/3.1",
    "C:\\Users\\Public\\svchost32.exe",
    "password=admin123",
    "bcdedit /set {default} recoveryenabled No",
    "aGVsbG8gdGhpcyBpcyBhIGRlbW8gcGF5bG9hZCBibG9iIGZvciB0cmlhZ2U=",
]

CLEAN_STRINGS = [
    "https://www.microsoft.com/en-us/download/details.aspx?id=99999",
    "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    "C:\\Program Files\\Contoso\\Updater\\contoso-updater.exe",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0",
    "Contoso Software Update Service",
    "10.0.0.5",
    "C:\\ProgramData\\Contoso\\Updater\\config.xml",
]

PACKED_DLLS: list[tuple[str, list[str]]] = [
    ("KERNEL32.dll", [
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "LoadLibraryA", "GetProcAddress", "CreateFileW",
    ]),
    ("WININET.dll", [
        "InternetOpenA", "InternetConnectA", "HttpSendRequestA", "URLDownloadToFileA",
    ]),
]

CLEAN_DLLS: list[tuple[str, list[str]]] = [
    ("KERNEL32.dll", [
        "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetModuleHandleW",
        "GetTickCount64", "QueryPerformanceCounter",
    ]),
    ("USER32.dll", ["MessageBoxW", "DispatchMessageW", "TranslateMessage"]),
    ("ADVAPI32.dll", ["RegOpenKeyExW", "RegQueryValueExW"]),
]


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _section_table_entry(
    name: str, vsize: int, rva: int, raw_size: int, raw_ptr: int, chars: int
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode("latin-1")[:8].ljust(8, b"\x00"),
        vsize, rva, raw_size, raw_ptr, 0, 0, 0, 0, chars,
    )


def _hint_name_blob(funcs: list[str], start_rva: int) -> tuple[bytes, list[int]]:
    blob = bytearray()
    rvas: list[int] = []
    cursor = start_rva
    for func in funcs:
        rvas.append(cursor)
        entry = struct.pack("<H", 0) + func.encode("latin-1") + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        blob += entry
        cursor += len(entry)
    return bytes(blob), rvas


def _build_rdata(
    dlls: list[tuple[str, list[str]]], with_debug: bool, timestamp: int
) -> tuple[bytes, int, int, int]:
    """Assemble .rdata and return (data, import_rva, import_size, debug_rva)."""
    buf = bytearray(RDATA_SIZE)

    def put(rva: int, data: bytes) -> None:
        off = rva - RDATA_RVA
        if off < 0 or off + len(data) > len(buf):
            raise ValueError("demo .rdata overflow - adjust the layout constants")
        buf[off:off + len(data)] = data

    # --- 1. reserve thunk arrays for each DLL (INT then IAT)
    cursor = 0x40
    int_rvas: list[int] = []
    iat_rvas: list[int] = []
    for _dll, funcs in dlls:
        int_rvas.append(RDATA_RVA + cursor)
        cursor += 4 * (len(funcs) + 1)
        iat_rvas.append(RDATA_RVA + cursor)
        cursor += 4 * (len(funcs) + 1)
    cursor = max(cursor + 0x10, 0xC0)

    # --- 2. hint/name tables
    hn_starts: list[int] = []
    hn_blobs: list[bytes] = []
    name_rvas: list[int] = []
    for _dll, funcs in dlls:
        start = RDATA_RVA + cursor
        blob, rvas = _hint_name_blob(funcs, start)
        hn_starts.append(start)
        hn_blobs.append(blob)
        name_rvas.extend(rvas)
        cursor += len(blob) + 0x10

    # --- 3. DLL name strings
    cursor = max(cursor + 0x10, 0x200)
    dll_name_rvas: list[int] = []
    for dll, _funcs in dlls:
        dll_name_rvas.append(RDATA_RVA + cursor)
        cursor += len(dll.encode("latin-1")) + 1 + 0x8

    debug_rva = RDATA_RVA + 0x300
    pdb_rva = RDATA_RVA + 0x340

    # --- 4. write everything
    descriptors = bytearray()
    for index, (_dll, _funcs) in enumerate(dlls):
        descriptors += struct.pack(
            "<IIIII", int_rvas[index], 0, 0, dll_name_rvas[index], iat_rvas[index]
        )
    descriptors += b"\x00" * 20  # terminator
    put(RDATA_RVA, bytes(descriptors))

    offset = 0
    for index, (_dll, funcs) in enumerate(dlls):
        thunks = b"".join(
            struct.pack("<I", rva) for rva in name_rvas[offset:offset + len(funcs)]
        ) + b"\x00\x00\x00\x00"
        put(int_rvas[index], thunks)
        put(iat_rvas[index], thunks)
        offset += len(funcs)

    for start, blob in zip(hn_starts, hn_blobs):
        put(start, blob)
    for index, (dll, _funcs) in enumerate(dlls):
        put(dll_name_rvas[index], dll.encode("latin-1") + b"\x00")

    if with_debug:
        # CODEVIEW record: 'RSDS' + GUID + age + NUL terminated PDB path.
        # pefile only populates PdbFileName when the RSDS signature is present.
        codeview = (
            b"RSDS"
            + bytes.fromhex("0123456789abcdef0123456789abcdef")
            + struct.pack("<I", 1)
            + b"D:\\builds\\rat\\Release\\client.pdb\x00"
        )
        put(pdb_rva, codeview)
        put(
            debug_rva,
            struct.pack(
                "<IIHHIIII",
                0, timestamp, 0, 0,
                2,  # IMAGE_DEBUG_TYPE_CODEVIEW
                len(codeview),
                pdb_rva,
                RDATA_RAW + (pdb_rva - RDATA_RVA),
            ),
        )

    import_size = (dll_name_rvas[-1] - RDATA_RVA) + 0x40
    return bytes(buf), RDATA_RVA, import_size, (debug_rva if with_debug else 0)


# --------------------------------------------------------------------------- #
#  public API
# --------------------------------------------------------------------------- #
def build_pe(variant: str = "packed", timestamp: int | None = None) -> bytes:
    """Build an inert PE image.

    ``packed`` - high-entropy final section, W+X, entry point inside the stub
    section, injection/network imports, C2 strings, embedded PDB path, no DEP
    and a trailing overlay.

    ``clean``  - benign release-style build with ordinary imports and strings,
    DEP/ASLR/CFG enabled and no overlay.
    """
    packed = variant != "clean"
    seed = 0xC0FFEE if packed else 0xBEEF
    rng = random.Random(seed)
    timestamp = timestamp if timestamp is not None else (0x7C000000 if packed else 0x665B0000)

    dlls = PACKED_DLLS if packed else CLEAN_DLLS
    rdata, import_rva, import_size, debug_rva = _build_rdata(
        dlls, with_debug=packed, timestamp=timestamp
    )

    # ------------------------------------------------------------------ .text
    if packed:
        text = bytes(rng.getrandbits(8) for _ in range(TEXT_SIZE))
    else:
        pattern = bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0xE8, 0x00] + [0x00] * 24)
        text = (pattern * (TEXT_SIZE // len(pattern) + 1))[:TEXT_SIZE]

    # ------------------------------------------------------------------ .data
    strings = PACKED_STRINGS if packed else CLEAN_STRINGS
    blob = bytearray()
    for item in strings:
        blob += item.encode("latin-1") + b"\x00"
    blob += "C:\\Users\\Public\\config.dat".encode("utf-16-le") + b"\x00\x00"
    if len(blob) > DATA_SIZE:
        raise ValueError("demo string block does not fit in .data")
    data = bytes(blob) + bytes(DATA_SIZE - len(blob))

    # ------------------------------------------------------- final section
    if packed:
        last_name, last_chars = "UPX0", 0xE0000020  # CNT_CODE | R | W | X
        last_data = bytes(rng.getrandbits(8) for _ in range(LAST_SIZE))
        entry_point = LAST_RVA + 0x100  # inside the packer stub
        dll_chars = 0x0000
    else:
        last_name, last_chars = ".rsrc", 0x40000040  # INITIALIZED_DATA | R
        last_data = bytes(16) + b"\x00\x00\x01\x00" + bytes(LAST_SIZE - 20)
        entry_point = TEXT_RVA + 0x100
        dll_chars = 0x8160  # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TS_AWARE

    # ------------------------------------------------------------- headers
    coff = struct.pack(
        "<HHIIIHH",
        0x14C,          # Machine: i386
        4,              # NumberOfSections
        timestamp,
        0, 0,
        0xE0,           # SizeOfOptionalHeader
        0x0102,         # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    optional = struct.pack(
        "<HBBIIIIII",
        0x10B, 14, 0,
        TEXT_SIZE,
        RDATA_SIZE + DATA_SIZE + LAST_SIZE,
        0,
        entry_point,
        TEXT_RVA,
        DATA_RVA,
    )
    optional += struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x400000, SECT_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0,
        0, SIZE_OF_IMAGE, SIZE_OF_HEADERS, 0,
        2, dll_chars,  # Subsystem = GUI, DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = [(0, 0)] * 16
    directories[1] = (import_rva, import_size)
    directories[6] = (debug_rva, 0x1C if debug_rva else 0)
    for rva, size in directories:
        optional += struct.pack("<II", rva, size)

    section_table = b"".join(
        [
            _section_table_entry(".text", TEXT_SIZE, TEXT_RVA, TEXT_SIZE, TEXT_RAW, 0x60000020),
            _section_table_entry(".rdata", RDATA_SIZE, RDATA_RVA, RDATA_SIZE, RDATA_RAW, 0x40000040),
            _section_table_entry(".data", DATA_SIZE, DATA_RVA, DATA_SIZE, DATA_RAW, 0xC0000040),
            _section_table_entry(last_name, LAST_SIZE, LAST_RVA, LAST_SIZE, LAST_RAW, last_chars),
        ]
    )

    out = bytearray(b"\x00" * SIZE_OF_HEADERS)
    out[0:2] = b"MZ"
    struct.pack_into("<H", out, 0x3C, 0x80)
    out[0x40:0x48] = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd"
    out[0x80:0x84] = b"PE\x00\x00"
    out[0x84:0x84 + len(coff)] = coff
    out[0x98:0x98 + len(optional)] = optional
    out[SECTION_TABLE_OFFSET:SECTION_TABLE_OFFSET + len(section_table)] = section_table
    if SECTION_TABLE_OFFSET + len(section_table) > SIZE_OF_HEADERS:  # pragma: no cover
        raise ValueError("section table does not fit before SizeOfHeaders")

    out += text + rdata + data + last_data
    if packed:
        out += bytes(rng.getrandbits(8) for _ in range(0x800))  # appended overlay
    return bytes(out)


def write_demo_samples(directory: str | Path) -> dict[str, Path]:
    """Write both demo variants into ``directory``; returns their paths."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    targets = {
        "packed": out / "demo_packed_sample.exe.SAMPLE",
        "clean": out / "demo_benign_update.exe.SAMPLE",
    }
    targets["packed"].write_bytes(build_pe("packed"))
    targets["clean"].write_bytes(build_pe("clean"))
    return targets
