"""JSON access that uses ``orjson`` when it is installed.

Sandbox reports are large (hundreds of megabytes is not unusual), so the parsing
layer prefers ``orjson`` when present and falls back to the standard library
otherwise.  Everything in the workbench goes through these two helpers so the
choice is made in exactly one place.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, BinaryIO

try:  # pragma: no cover - depends on the environment
    import orjson

    ENGINE = "orjson"
except Exception:  # pragma: no cover
    orjson = None
    ENGINE = "stdlib json"


def loads(data: bytes | str) -> Any:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if orjson is not None:
        return orjson.loads(data)
    return json.loads(data.decode("utf-8", "replace"))


def load_path(path: str | Path) -> Any:
    return loads(Path(path).read_bytes())


def load_stream(handle: BinaryIO) -> Any:
    return loads(handle.read())


def dumps(value: Any, *, indent: int | None = 1) -> str:
    if orjson is not None and indent is None:
        return orjson.dumps(value).decode("utf-8")
    return json.dumps(value, indent=indent, default=str)


def iter_jsonl(text: str):
    """Yield parsed JSON Lines, skipping blank or malformed lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            yield loads(line)
        except Exception:
            continue
