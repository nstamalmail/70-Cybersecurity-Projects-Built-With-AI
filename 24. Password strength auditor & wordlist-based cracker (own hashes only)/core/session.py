"""Session state and atomic checkpoint persistence.

Everything is written under the operator-chosen base_dir only:

    <base_dir>/sessions/session.json
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SESSION_DIR = "sessions"
SESSION_FILE = "session.json"
FORMAT_VERSION = 1


def _atomic_write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
    os.replace(tmp, path)


@dataclass
class AttackConfig:
    mode: str = "dictionary"            # dictionary | rules | mask | combinator
    wordlist: str = ""
    rules_file: str = ""
    mask: str = "?d?d?d?d"
    wordlist2: str = ""                 # combinator only
    max_candidates: int = 1_000_000

    def to_dict(self) -> dict:
        return {
            "mode": self.mode, "wordlist": self.wordlist,
            "rules_file": self.rules_file, "mask": self.mask,
            "wordlist2": self.wordlist2, "max_candidates": self.max_candidates,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackConfig":
        return cls(
            mode=d.get("mode", "dictionary"),
            wordlist=d.get("wordlist", ""),
            rules_file=d.get("rules_file", ""),
            mask=d.get("mask", "?d?d?d?d"),
            wordlist2=d.get("wordlist2", ""),
            max_candidates=int(d.get("max_candidates", 1_000_000)),
        )


@dataclass
class SessionState:
    records: List[HashRecord] = field(default_factory=list)
    config: AttackConfig = field(default_factory=AttackConfig)
    started_at: float = 0.0
    last_checkpoint: float = 0.0
    candidates_tried: int = 0
    cracked: Dict[str, str] = field(default_factory=dict)   # digest_hex -> plaintext
    cracked_by: Dict[str, str] = field(default_factory=dict)  # digest_hex -> mode
    finished: bool = False

    def to_dict(self) -> dict:
        return {
            "format_version": FORMAT_VERSION,
            "started_at": self.started_at,
            "last_checkpoint": self.last_checkpoint or time.time(),
            "candidates_tried": self.candidates_tried,
            "finished": self.finished,
            "config": self.config.to_dict(),
            "records": [
                {
                    "raw": r.raw, "algo": r.algo, "digest_hex": r.digest_hex,
                    "salt": r.salt, "label": r.label, "identified": r.identified,
                    "plaintext": r.plaintext, "cracked_by": r.cracked_by,
                    "verdict": r.verdict, "entropy_bits": r.entropy_bits,
                    "findings": r.findings,
                }
                for r in self.records
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        from .parser import HashRecord
        st = cls()
        st.started_at = float(d.get("started_at", 0))
        st.last_checkpoint = float(d.get("last_checkpoint", 0))
        st.candidates_tried = int(d.get("candidates_tried", 0))
        st.finished = bool(d.get("finished", False))
        st.config = AttackConfig.from_dict(d.get("config", {}))
        for rd in d.get("records", []):
            rec = HashRecord(
                raw=rd.get("raw", ""),
                algo=rd.get("algo"),
                digest_hex=rd.get("digest_hex", ""),
                salt=rd.get("salt"),
                label=rd.get("label", ""),
                identified=bool(rd.get("identified", False)),
                plaintext=rd.get("plaintext"),
                cracked_by=rd.get("cracked_by", ""),
                verdict=rd.get("verdict", ""),
                entropy_bits=float(rd.get("entropy_bits", 0)),
                findings=list(rd.get("findings", [])),
            )
            st.records.append(rec)
            if rec.plaintext:
                st.cracked[rec.digest_hex] = rec.plaintext
        return st

    def save(self, base_dir: str) -> str:
        path = os.path.join(base_dir, SESSION_DIR, SESSION_FILE)
        _atomic_write_json(path, self.to_dict())
        return path

    @classmethod
    def load(cls, base_dir: str) -> Optional["SessionState"]:
        path = os.path.join(base_dir, SESSION_DIR, SESSION_FILE)
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            try:
                d = json.load(fh)
            except json.JSONDecodeError:
                return None
        return cls.from_dict(d)

    def clear(self, base_dir: str) -> None:
        clear_session_file(base_dir)


def clear_session_file(base_dir: str) -> None:
    """Delete the session checkpoint file under *base_dir*, if present."""
    path = os.path.join(base_dir, SESSION_DIR, SESSION_FILE)
    if os.path.isfile(path):
        os.remove(path)
