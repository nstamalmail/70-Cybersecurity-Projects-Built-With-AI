"""Core domain models for RECT (Reverse-Engineering CTF Solver Toolkit)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CATEGORIES = ["rev", "crypto", "pwn", "misc", "forensics"]


@dataclass
class BinaryInfo:
    """Static information extracted from a loaded file."""

    path: str
    size: int = 0
    file_type: str = ""            # 'elf', 'pe', 'macho', 'raw', 'text', ...
    architecture: str = ""          # 'x86', 'x64', 'arm', ...
    bits: int = 0
    endianness: str = ""            # 'little', 'big'
    packed: bool = False
    entropy: float = 0.0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    strings: List[Dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "size": self.size, "file_type": self.file_type,
            "architecture": self.architecture, "bits": self.bits,
            "endianness": self.endianness, "packed": self.packed,
            "entropy": self.entropy, "sections": self.sections,
            "imports": self.imports, "strings_count": len(self.strings),
            "notes": self.notes,
        }


@dataclass
class AnalysisRecord:
    """One solver action (decode/xor/hash/analysis) kept for the writeup."""

    tool: str                       # 'encoding', 'xor', 'hash_id', 'strings', ...
    operation: str                  # human name e.g. 'base64 decode'
    input_summary: str = ""
    output_summary: str = ""
    full_output: str = ""
    success: bool = True
    ts: float = field(default_factory=time.time)
    id: Optional[int] = None
    challenge_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "challenge_id": self.challenge_id,
            "tool": self.tool, "operation": self.operation,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "full_output": self.full_output, "success": self.success,
            "ts": self.ts,
        }

    def summary(self) -> str:
        mark = "✔" if self.success else "✖"
        return f"{mark} {self.tool}/{self.operation}: {self.output_summary[:90]}"


@dataclass
class Challenge:
    """A CTF challenge case (one workspace)."""

    name: str
    category: str = "rev"           # 'rev', 'crypto', 'pwn', 'misc'
    event: str = ""
    description: str = ""
    flag_format: str = "flag{"      # e.g. 'flag{', 'CTF{', 'picoCTF{'
    binary_path: str = ""
    solved: bool = False
    flag: str = ""
    notes_md: str = ""
    created_at: float = field(default_factory=time.time)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "event": self.event, "description": self.description,
            "flag_format": self.flag_format, "binary_path": self.binary_path,
            "solved": self.solved, "flag": self.flag,
            "notes_md": self.notes_md, "created_at": self.created_at,
        }


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, indent=2)
