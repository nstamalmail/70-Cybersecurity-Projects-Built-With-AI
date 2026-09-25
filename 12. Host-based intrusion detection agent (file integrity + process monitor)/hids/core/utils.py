"""Small shared helpers: hashing, path matching, app/data directory resolution."""

import fnmatch
import hashlib
import sys
import time
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def now() -> float:
    return time.time()


def ts_str(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (TypeError, ValueError, OverflowError):
        return str(ts)


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_root() -> Path:
    """Directory the (portable) app lives in; next to exe when frozen."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def default_data_dir() -> Path:
    """Data dir next to the app (portable), with home-dir fallback if unwritable."""
    candidates = [app_root() / "data", Path.home() / ".hids-agent" / "data"]
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return d
        except OSError:
            continue
    raise RuntimeError("No writable data directory available")


def sha256_file(path, max_bytes=None, chunk=CHUNK_SIZE):
    """Chunked SHA-256. Returns hex digest, or None if unreadable/too large."""
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                size += len(block)
                if max_bytes is not None and size > max_bytes:
                    return None
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def path_excluded(path, patterns) -> bool:
    """fnmatch-based exclusion supporting:
      - wildcards:        '*.log', '*/.git/*'
      - dir prefixes:     'C:/Windows/Temp/'  or component 'skipme/'
      - bare names:       'pagefile.sys' (matches basename or exact path)
    Comparison is case-insensitive and slash-normalized.
    """
    norm = str(path).replace("\\", "/").lower()
    base = norm.rsplit("/", 1)[-1]
    for raw in patterns or []:
        pat = str(raw).replace("\\", "/").lower().strip()
        if not pat:
            continue
        if pat.endswith("/"):
            prefix = pat.rstrip("/")
            if not prefix:
                continue
            if norm == prefix or norm.startswith(prefix + "/"):
                return True
            # match as any path component (e.g. 'skipme/' hits .../x/skipme/y)
            if f"/{prefix}/" in f"/{norm}/":
                return True
            if base == prefix:
                return True
            if "*" in prefix or "?" in prefix:
                segments = norm.split("/")
                for i in range(len(segments)):
                    if fnmatch.fnmatch("/".join(segments[i:]), prefix + "/*") or \
                            fnmatch.fnmatch("/".join(segments[i:]), prefix):
                        return True
            continue
        if "*" in pat or "?" in pat:
            if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(base, pat):
                return True
            continue
        if norm == pat or norm.startswith(pat + "/") or base == pat:
            return True
    return False
