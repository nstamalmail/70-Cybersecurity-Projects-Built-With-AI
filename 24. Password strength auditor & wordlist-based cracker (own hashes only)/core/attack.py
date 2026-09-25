"""Attack engine: dictionary / rules / mask / combinator candidate generation.

Design notes (see architecture.md §5.7):
    - Candidate generation is a generator; the GUI worker pulls in chunks.
    - A legal-authorization gate is enforced HERE, not only in the UI.
    - Stop semantics via threading.Event; checkpoint dict emitted periodically.
    - Mask mode is hard-capped at max_candidates with pre-start math.
"""

from __future__ import annotations

import itertools
import threading
import time
from typing import Callable, Dict, Iterator, List, Optional, Set

from . import rules as rule_mod
from .hashes import ALGORITHMS, get
from .parser import HashRecord
from .policy import audit_record
from .session import AttackConfig

CHARSETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ",
    "b": "".join(chr(i) for i in range(0x20, 0x7F)),
    "a": ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
          "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ "),
}

MASK_PRESETS = {
    "4 digits": "?d?d?d?d",
    "6 digits": "?d?d?d?d?d?d",
    "8 digits": "?d?d?d?d?d?d?d?d",
    "Word + 2 digits (lower)": "?l?l?l?l?l?l?d?d",
    "CapWord + 3 digits": "?u?l?l?l?l?l?d?d?d",
}

MAX_MASK_POSITIONS = 12


class LegalGateRequired(RuntimeError):
    """Raised when an attack is started without legal authorization."""


class AttackEngine:
    """Runs one attack against an in-memory registry of records.

    The engine owns the authorization gate: `start()` refuses to run unless
    `authorize(True)` was called for this exact run (defense in depth — the
    GUI checkbox alone is not trusted).
    """

    def __init__(self, records: List[HashRecord], config: AttackConfig,
                 authorized: bool = False):
        self.records = [r for r in records if r.digest_hex]
        self.config = config
        self._authorized = authorized
        self.stop_event = threading.Event()
        self.warnings: List[str] = []

        # Registry keyed by digest for O(1) lookups; salted records handled
        # via per-record digest functions set up in _build_targets().
        self.registry: Dict[str, HashRecord] = {r.digest_hex: r for r in self.records}

        self.candidates_tried = 0
        self.found_count = 0
        self.rate = 0.0
        self.eta_seconds = 0.0
        self.total_estimate = 0
        self.finished = False
        self.error: Optional[str] = None

    # -- authorization -----------------------------------------------------

    def authorize(self, value: bool) -> None:
        self._authorized = bool(value)

    def _gate(self) -> None:
        if not self._authorized:
            raise LegalGateRequired(
                "Attack refused: legal authorization not acknowledged "
                "(own hashes / authorized systems only)."
            )

    # -- candidate generators ----------------------------------------------

    @staticmethod
    def _mask_charset(mask: str) -> Optional[List[str]]:
        """Parse mask into per-position charset strings; None if invalid."""
        groups: List[str] = []
        i = 0
        while i < len(mask):
            if mask[i] == "?" and i + 1 < len(mask):
                key = mask[i + 1].lower()
                if key == "h":
                    key = "d"  # hex-ish alias in our presets
                if key not in CHARSETS:
                    return None
                groups.append(CHARSETS[key])
                i += 2
            elif mask[i] == "?":
                return None  # dangling '?'
            else:
                # Literal run
                j = i
                while j < len(mask) and mask[j] != "?":
                    j += 1
                groups.append(mask[i:j])
                i = j
        if not groups or len(groups) > MAX_MASK_POSITIONS:
            return None
        return groups

    def mask_count(self, mask: str) -> int:
        groups = self._mask_charset(mask)
        if groups is None:
            return 0
        total = 1
        for g in groups:
            total *= max(len(g), 1)
        return total

    def _iter_mask(self, mask: str) -> Iterator[str]:
        groups = self._mask_charset(mask)
        if not groups:
            return
        for combo in itertools.product(*groups):
            yield "".join(combo)

    @staticmethod
    def _parse_inc_arg(arg: str) -> int:
        try:
            return max(1, int(arg))
        except (TypeError, ValueError):
            return 1

    def _iter_dictionary(self, words: List[str]) -> Iterator[str]:
        for w in words:
            yield w

    def _iter_rules(self, words: List[str], rule_lines: List[List[Callable]]) -> Iterator[str]:
        for w in words:
            for ops in rule_lines:
                out = rule_mod.apply_rule(w, ops)
                if out:
                    yield out

    def _iter_combinator(self, words1: List[str], words2: List[str]) -> Iterator[str]:
        for a, b in itertools.product(words1, words2):
            yield a + b

    def _candidate_stream(self) -> Iterator[str]:
        cfg = self.config
        if cfg.mode == "dictionary":
            words = self._words_for(cfg.wordlist)
            return self._iter_dictionary(words)
        if cfg.mode == "rules":
            words = self._words_for(cfg.wordlist)
            lines, problems = rule_mod.load_rules_file(cfg.rules_file)
            if problems:
                self.warnings.extend(problems[:50])
            return self._iter_rules(words, lines)
        if cfg.mode == "mask":
            return self._iter_mask(cfg.mask)
        if cfg.mode == "combinator":
            return self._iter_combinator(
                self._words_for(cfg.wordlist), self._words_for(cfg.wordlist2))
        raise ValueError(f"Unknown attack mode: {cfg.mode}")

    def _words_for(self, path: str) -> List[str]:
        if not path:
            raise ValueError("No wordlist selected.")
        from .wordlists import load_wordlist
        return load_wordlist(path)

    # -- targets ------------------------------------------------------------

    def _build_targets(self) -> Dict[bytes, List[HashRecord]]:
        """Map raw digest bytes -> records, with per-record digest callables."""
        targets: Dict[bytes, List[HashRecord]] = {}

        def add(digest_bytes: bytes, rec: HashRecord) -> None:
            targets.setdefault(digest_bytes, []).append(rec)

        for rec in self.records:
            algo = rec.algo
            if not algo:
                # Unidentified: try all 32-hex candidates (md5/ntlm/md4).
                for name in ("md5", "ntlm", "md4"):
                    if get(name).hexlen == len(rec.digest_hex):
                        try:
                            add(bytes.fromhex(rec.digest_hex), rec)
                        except ValueError:
                            pass
                        break
                continue
            h = get(algo)
            if algo == "sha512crypt":
                salt = (rec.salt or "").encode("utf-8", "replace")
                from .hashes import _sha512_crypt_digest
                def make_digest(rec_salt: bytes):
                    def d(data: bytes) -> bytes:
                        out, _ = _sha512_crypt_digest(data, rec_salt)
                        return out
                    return d
                rec_digest = make_digest(salt)
            else:
                rec_digest = h.digest
            try:
                raw = bytes.fromhex(rec.digest_hex)
            except ValueError:
                continue
            rec._digest_fn = rec_digest  # type: ignore[attr-defined]
            add(raw, rec)
        return targets

    # -- main run ------------------------------------------------------------

    def run(self, progress_cb: Optional[Callable[[dict], None]] = None,
            chunk: int = 2048) -> Dict[str, object]:
        """Execute the attack. Blocking; call from a worker thread only."""
        self._gate()
        self.started = time.time()
        targets = self._build_targets()
        found_new: List[tuple] = []
        last_tick = self.started
        last_count = 0

        stream = self._candidate_stream()

        try:
            while True:
                if self.stop_event.is_set():
                    break
                batch = list(itertools.islice(stream, chunk))
                if not batch:
                    self.finished = True
                    break

                hits = self._match_batch(batch, targets)
                self.candidates_tried += len(batch)
                for pw, matched in hits:
                    for rec, algo in matched:
                        if rec.plaintext is None:
                            rec.plaintext = pw
                            rec.cracked_by = self.config.mode
                            if algo:
                                rec.algo = algo       # confirmed by crack
                                rec.identified = True
                            self.found_count += 1
                            found_new.append((rec, pw))
                if self.found_count >= len(self.records) and self.records:
                    # Every target cracked — no point burning the remaining keyspace.
                    self.finished = True
                    break

                now = time.time()
                if now - last_tick >= 0.25:
                    inst = (self.candidates_tried - last_count) / max(now - last_tick, 1e-6)
                    self.rate = 0.7 * inst + 0.3 * self.rate if self.rate else inst
                    last_tick, last_count = now, self.candidates_tried
                    if self.total_estimate:
                        remaining = max(self.total_estimate - self.candidates_tried, 0)
                        self.eta_seconds = remaining / max(self.rate, 1.0)
                    if progress_cb:
                        progress_cb(self.snapshot())
        except Exception as exc:  # fail-closed: surface, don't die silently
            self.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            # Final audit pass on cracked records.
            for rec in self.records:
                if rec.plaintext:
                    audit_record(rec)
            if progress_cb:
                progress_cb(self.snapshot())

        return {
            "finished": self.finished,
            "stopped": self.stop_event.is_set(),
            "error": self.error,
            "candidates": self.candidates_tried,
            "found": self.found_count,
            "new": [(r.display_name(), pw) for r, pw in found_new],
            "rate": self.rate,
        }

    def _match_batch(self, batch: List[str], targets: Dict[bytes, List[HashRecord]]):
        """Digest every candidate once per distinct algorithm and look up.

        Returns list of (password, [(record, algo_name), ...]) so the caller can
        confirm the algorithm on unidentified records that cracked.
        """
        hits = []
        # Group records by algorithm to reuse digest calls across candidates.
        by_algo: Dict[str, List[HashRecord]] = {}
        for recs in targets.values():
            for rec in recs:
                by_algo.setdefault(rec.algo or "unknown32", []).append(rec)

        algos = set(by_algo.keys())

        for pw in batch:
            encoded = pw.encode("utf-8", "replace")
            # raw digest -> list[(record, algo)]
            raw_map: Dict[bytes, List[tuple]] = {}
            for algo in algos:
                if algo == "sha512crypt":
                    # Slow KDF: per-record salted digest.
                    for rec in by_algo["sha512crypt"]:
                        fn = getattr(rec, "_digest_fn", None)
                        if fn:
                            raw_map.setdefault(fn(encoded), []).append((rec, "sha512crypt"))
                    continue
                if algo == "unknown32":
                    for name in ("md5", "ntlm", "md4"):
                        d = get(name).digest(encoded)
                        raw_map.setdefault(d, []).extend(
                            (r, name) for r in by_algo["unknown32"]
                            if r.algo is None and len(r.digest_hex) == len(d.hex()))
                    continue
                h = get(algo)
                d = h.digest(encoded)
                raw_map.setdefault(d, []).extend((r, algo) for r in by_algo[algo])

            for raw, matched in raw_map.items():
                match = targets.get(raw)
                if match:
                    hits.append((pw, matched))
        return hits

    def snapshot(self) -> dict:
        elapsed = max(time.time() - getattr(self, "started", time.time()), 1e-6)
        return {
            "candidates": self.candidates_tried,
            "found": self.found_count,
            "rate": self.rate,
            "eta": self.eta_seconds,
            "total": self.total_estimate,
            "elapsed": elapsed,
            "finished": self.finished,
        }
