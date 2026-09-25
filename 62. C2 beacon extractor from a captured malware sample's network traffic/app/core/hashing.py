"""Hash helpers: streaming digests, entropy, magic-byte typing."""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

CHUNK = 1024 * 1024

_MAGIC_TYPES: list[tuple[bytes, str]] = [
    (b"MZ", "PE executable (Windows)"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP / Office document"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "OLE compound document (Office 97-2003)"),
    (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"7z\xbc\xaf", "7-Zip archive"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"#!", "Script (shebang)"),
]


def compute_hashes(path: str | Path, max_bytes: int | None = None) -> dict:
    """Compute MD5, SHA-1 and SHA-256 in a single pass over the file."""
    p = Path(path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    read = 0
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            if max_bytes is not None and read + len(chunk) > max_bytes:
                chunk = chunk[: max_bytes - read]
            if not chunk:
                break
            read += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    size = p.stat().st_size
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
        "hashed_bytes": read,
    }


def compute_hashes_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "hashed_bytes": len(data),
    }


def hash_type(value: str) -> str | None:
    """Auto-detect the hash family from a hex digest length."""
    value = (value or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", value or " "):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return round(value, 4)


def file_type(path: str | Path, head: bytes | None = None) -> str:
    """Best-effort file type from magic bytes."""
    p = Path(path)
    if head is None:
        try:
            with p.open("rb") as fh:
                head = fh.read(16)
        except Exception:
            return "unknown"
    if head[:2] == b"MZ":
        return "PE executable (Windows)"
    for magic, label in _MAGIC_TYPES:
        if head.startswith(magic):
            return label
    suffix = p.suffix.lower()
    if suffix in (".txt", ".log", ".json", ".xml", ".csv", ".md", ".yml", ".yaml"):
        return f"text ({suffix.lstrip('.')})"
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:8]):
        return "text (ascii)"
    return "unknown / raw"


def is_pe(path: str | Path) -> bool:
    try:
        with Path(path).open("rb") as fh:
            return fh.read(2) == b"MZ"
    except Exception:
        return False


def human_size(num: int | float) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


def try_hash(path: str | Path | None, algo: str = "sha256") -> str:
    """Best-effort digest of a file, returning ``""`` when it is unreadable."""
    if not path:
        return ""
    try:
        import hashlib

        digest = hashlib.new(algo)
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return ""
