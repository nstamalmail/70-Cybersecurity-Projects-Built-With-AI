"""Minimal BSON codec for CAPE behaviour logs (architecture §3.3 / §9).

CAPE writes its behaviour logs as BSON (``.bson``), optionally wrapped in a
compression layer.  A full BSON implementation is not needed to read them: the
subset below covers every type that appears in a behaviour log —

===========  ==========================================================
0x01 double  8-byte IEEE-754
0x02 string  int32 length + UTF-8 + NUL
0x03 document nested document
0x04 array   document with numeric string keys
0x05 binary  int32 length + subtype + bytes
0x08 bool    1 byte
0x09 UTC datetime  int64 milliseconds
0x0A null
0x10 int32
0x12 int64
===========  ==========================================================

plus the deprecated-but-common 0x07 ObjectId and 0x11 timestamp, which are kept
as raw bytes so nothing is silently dropped.

The module also *encodes* BSON, which is what the demo fixtures use to produce a
realistic CAPE-style log without shipping a binary blob.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

INT32 = 0x10
INT64 = 0x12
DOUBLE = 0x01
STRING = 0x02
DOCUMENT = 0x03
ARRAY = 0x04
BINARY = 0x05
OBJECTID = 0x07
BOOL = 0x08
DATETIME = 0x09
NULL = 0x0A
TIMESTAMP = 0x11


class BsonError(ValueError):
    pass


def _read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end < 0:
        raise BsonError("unterminated cstring")
    return data[offset:end].decode("utf-8", "replace"), end + 1


def decode_document(data: bytes, offset: int = 0) -> tuple[dict, int]:
    """Decode one document starting at ``offset``; returns ``(document, next)``."""
    if offset + 4 > len(data):
        raise BsonError("truncated document header")
    size = struct.unpack_from("<i", data, offset)[0]
    if size < 5 or offset + size > len(data):
        raise BsonError(f"invalid document size {size} at offset {offset}")
    cursor = offset + 4
    end = offset + size - 1
    out: dict = {}
    while cursor < end:
        element_type = data[cursor]
        cursor += 1
        key, cursor = _read_cstring(data, cursor)
        if element_type == DOUBLE:
            value = struct.unpack_from("<d", data, cursor)[0]
            cursor += 8
        elif element_type == STRING:
            length = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4
            if length < 1:
                value = ""
            else:
                value = data[cursor : cursor + length - 1].decode("utf-8", "replace")
                cursor += length
        elif element_type == DOCUMENT:
            value, cursor = decode_document(data, cursor)
        elif element_type == ARRAY:
            nested, cursor = decode_document(data, cursor)
            value = [nested[key] for key in sorted(nested, key=lambda k: int(k))] if nested else []
        elif element_type == BINARY:
            length = struct.unpack_from("<i", data, cursor)[0]
            subtype = data[cursor + 4]
            cursor += 5
            raw = data[cursor : cursor + length]
            cursor += length
            value = raw if subtype == 0 else raw.hex()
        elif element_type == OBJECTID:
            value = data[cursor : cursor + 12].hex()
            cursor += 12
        elif element_type == BOOL:
            value = data[cursor] != 0
            cursor += 1
        elif element_type == DATETIME:
            millis = struct.unpack_from("<q", data, cursor)[0]
            cursor += 8
            value = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=millis)).isoformat()
        elif element_type == NULL:
            value = None
        elif element_type == INT32:
            value = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4
        elif element_type == INT64:
            value = struct.unpack_from("<q", data, cursor)[0]
            cursor += 8
        elif element_type == TIMESTAMP:
            value = struct.unpack_from("<q", data, cursor)[0]
            cursor += 8
        else:
            raise BsonError(f"unsupported BSON element type 0x{element_type:02x} for key {key!r}")
        out[key] = value
    return out, offset + size


def decode(data: bytes) -> dict:
    document, _next = decode_document(data, 0)
    return document


def decode_all(data: bytes) -> list[dict]:
    """Decode every consecutive document in a stream (CAPE appends documents)."""
    documents: list[dict] = []
    offset = 0
    while offset + 4 <= len(data):
        try:
            document, offset = decode_document(data, offset)
        except BsonError:
            break
        documents.append(document)
    return documents


# --------------------------------------------------------------------------- #
#  Encoding (fixtures and round-trip tests)
# --------------------------------------------------------------------------- #
def _cstring(value: str) -> bytes:
    return value.encode("utf-8") + b"\x00"


def _element(key: str, value) -> bytes:
    if isinstance(value, bool):
        return bytes([BOOL]) + _cstring(key) + bytes([1 if value else 0])
    if value is None:
        return bytes([NULL]) + _cstring(key)
    if isinstance(value, int):
        if -2**31 <= value < 2**31:
            return bytes([INT32]) + _cstring(key) + struct.pack("<i", value)
        return bytes([INT64]) + _cstring(key) + struct.pack("<q", value)
    if isinstance(value, float):
        return bytes([DOUBLE]) + _cstring(key) + struct.pack("<d", value)
    if isinstance(value, bytes):
        return bytes([BINARY]) + _cstring(key) + struct.pack("<i", len(value)) + b"\x00" + value
    if isinstance(value, str):
        encoded = value.encode("utf-8") + b"\x00"
        return bytes([STRING]) + _cstring(key) + struct.pack("<i", len(encoded)) + encoded
    if isinstance(value, dict):
        return bytes([DOCUMENT]) + _cstring(key) + encode(value)
    if isinstance(value, (list, tuple)):
        array = {str(index): item for index, item in enumerate(value)}
        return bytes([ARRAY]) + _cstring(key) + encode(array)
    raise BsonError(f"cannot encode {type(value).__name__} for key {key!r}")


def encode(document: dict) -> bytes:
    body = b"".join(_element(str(key), value) for key, value in document.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def is_bson(data: bytes) -> bool:
    """Cheap sniff: length-prefixed document that decodes cleanly."""
    if len(data) < 5:
        return False
    size = struct.unpack_from("<i", data, 0)[0]
    if size < 5 or size > len(data):
        return False
    try:
        decode_document(data, 0)
    except Exception:
        return False
    return True
