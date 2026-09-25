"""Hash line parser and in-memory registry for HashArmor.

Accepted line formats (blank lines and `#` comments skipped):

    <hash>
    <hash>:<salt>
    <hash>:<salt>:<label>
    <label>::<hash>            (loose form; last hex token wins)

The identifier is heuristic: digest hex length maps to candidate algorithms
(32 -> md5/md4/ntlm, 40 -> sha1, 64 -> sha256, 128 -> sha512), and
`$6$rounds=N$salt$hex` maps to sha512crypt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

LENGTH_ALGOS = {
    32: ["md5", "ntlm", "md4"],
    40: ["sha1"],
    64: ["sha256"],
    128: ["sha512"],
}


@dataclass
class HashRecord:
    raw: str
    algo: Optional[str] = None
    digest_hex: str = ""
    salt: Optional[str] = None
    label: str = ""
    identified: bool = False
    plaintext: Optional[str] = None
    cracked_by: str = ""          # attack mode that found it
    findings: List[str] = field(default_factory=list)
    verdict: str = ""             # filled by policy audit
    entropy_bits: float = 0.0

    def display_name(self) -> str:
        return self.label or (self.digest_hex[:16] + ("…" if len(self.digest_hex) > 16 else ""))


def _clean(line: str) -> str:
    return line.strip().strip("[]").strip()


def identify(token: str) -> List[str]:
    """Return candidate algorithm names for a hex digest token."""
    t = token.strip().lower()
    if "$6$" in token or token.startswith("$6$"):
        return ["sha512crypt"]
    if not HEX_RE.match(t):
        return []
    return LENGTH_ALGOS.get(len(t), [])


def parse_line(line: str) -> Optional[HashRecord]:
    """Parse one hash-file line into a HashRecord, or None if unparseable."""
    s = _clean(line)
    if not s or s.startswith("#"):
        return None

    # sha512-crypt style: $6$rounds=N$salt$digest (digest = 86 chars of the
    # crypt base64 alphabet ./0-9A-Za-z, per the sha-crypt spec).
    m = re.match(r"^\$6\$(?:rounds=(\d+)\$)?([^$]{0,16})\$([./0-9A-Za-z]{86})$", s)
    if m:
        rounds = m.group(1)
        salt = m.group(2)
        hexd = m.group(3).lower()
        return HashRecord(
            raw=s, algo="sha512crypt", digest_hex=hexd,
            salt=(f"rounds={rounds}$" if rounds else "") + salt,
            identified=True,
        )

    # Loose split — handle both 'hash:salt:label' and 'label::hash' shapes.
    parts = [p for p in s.split(":")]
    hex_tokens = [p for p in parts if HEX_RE.match(p) and len(p) in LENGTH_ALGOS]
    if not hex_tokens:
        return None

    hexd = hex_tokens[-1].lower()
    algos = identify(hexd)
    algo = algos[0] if len(algos) == 1 else None

    # Salt/label disambiguation. Accepted shapes:
    #   hash:salt | hash:salt:label | label:hash | label::hash
    # A field positioned BEFORE the digest is a label; fields AFTER it are
    # salt (first) then label (last) when two are present.
    salt = None
    label = ""
    if len(parts) >= 2:
        hex_pos = s.find(hexd)
        nonempty = [p for p in parts if p and p != hexd and p != hexd.upper()]
        if len(nonempty) == 1:
            one = nonempty[0]
            if 0 <= s.find(one) < hex_pos:
                label = one
            else:
                salt = one
        elif len(nonempty) >= 2:
            if 0 <= s.find(nonempty[0]) < hex_pos:
                label = nonempty[0]
                salt = nonempty[1] if len(nonempty) > 1 else None
            else:
                salt = nonempty[0]
                label = nonempty[-1]

    rec = HashRecord(raw=s, algo=algo, digest_hex=hexd, salt=salt,
                     label=label, identified=algo is not None)
    return rec


def parse_text(text: str) -> List[HashRecord]:
    """Parse a block of hash-file text into records (duplicates merged)."""
    seen: Dict[str, HashRecord] = {}
    order: List[HashRecord] = []
    for line in text.splitlines():
        rec = parse_line(line)
        if rec is None:
            continue
        key = rec.digest_hex
        if key in seen:
            continue
        seen[key] = rec
        order.append(rec)
    return order


def load_hash_file(path: str) -> List[HashRecord]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_text(fh.read())


def plaintext_export(records: List[HashRecord]) -> List[tuple]:
    """(label, algo, digest, plaintext) tuples for reports — sorted, deterministic."""
    rows = [(r.display_name(), r.algo or "?", r.digest_hex, r.plaintext or "")
            for r in records]
    return sorted(rows, key=lambda t: (t[0], t[1], t[2]))
