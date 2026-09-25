"""Analysis worker for RECT.

Long-running operations (entropy, strings, brute force) run in a worker
thread and push event dicts into the GUI queue. Operations are also logged as
AnalysisRecords so the writeup builder can replay the solution.
"""

from __future__ import annotations

import os
import queue
import threading
from typing import Optional

from app.core import crypto_kit as ck
from app.core.loader import load_binary, shannon_entropy
from app.core.models import AnalysisRecord


class AnalysisEngine(threading.Thread):
    """Runs a named operation against a target file or text value."""

    def __init__(self, op: str, events: "queue.Queue", *,
                 file_path: str = "", value: str = "",
                 key: str = "", encoding: str = "",
                 flag_format: str = "flag{"):
        super().__init__(daemon=True)
        self.op = op
        self.events = events
        self.file_path = file_path
        self.value = value
        self.key = key
        self.encoding = encoding
        self.flag_format = flag_format
        self.result: AnalysisRecord = AnalysisRecord(tool=op, operation=op)
        self.error = ""

    # ------------------------------------------------------------------ utils
    def _emit(self, ev_type: str, **kw) -> None:
        self.events.put({"type": ev_type, **kw})

    def _log(self, msg: str) -> None:
        self._emit("log", message=msg)

    def _load(self) -> bytes:
        with open(self.file_path, "rb") as fh:
            return fh.read(8_000_000)

    def _find_flags(self, text: str) -> str:
        import re
        pat = re.escape(self.flag_format).rstrip("}")
        flags = re.findall(pat + r"[^}\s]{0,80}}", text)
        return ", ".join(flags[:5])

    # ------------------------------------------------------------------ main
    def run(self) -> None:
        try:
            getattr(self, f"_op_{self.op}")()
            self.result.success = not self.error
        except Exception as exc:  # noqa: BLE001
            self.error = f"{exc.__class__.__name__}: {exc}"
            self.result.success = False
            self.result.output_summary = self.error
        if self.error:
            self._log(f"[{self.op}] error: {self.error}")
        self._emit("op_done", record=self.result, error=self.error)

    # ------------------------------------------------------------------ ops
    def _op_load(self) -> None:
        if not self.file_path or not os.path.exists(self.file_path):
            self.error = "file not found"
            return
        self._emit("status", message=f"Loading {os.path.basename(self.file_path)}…")
        info = load_binary(self.file_path)
        self._emit("binary_loaded", info=info)
        summary = (f"{info.file_type}, {info.architecture or 'unknown arch'}, "
                   f"{info.bits or '?'}-bit, entropy {info.entropy:.2f}, "
                   f"{len(info.strings)} strings"
                   + (", PACKED" if info.packed else ""))
        self.result = AnalysisRecord(
            tool="loader", operation="binary load",
            input_summary=os.path.basename(self.file_path),
            output_summary=summary, full_output=summary,
            success=True)
        self._log(f"Loaded: {summary}")
        flags = self._find_flags("\n".join(s["text"] for s in info.strings))
        if flags:
            self._log(f"🚩 flag-like strings: {flags}")
        self.result = self.result  # keep

    def _op_strings(self) -> None:
        if not self.file_path:
            self.error = "no file loaded"
            return
        info = load_binary(self.file_path)
        interesting = [s for s in info.strings
                       if s.get("class") not in ("general",)]
        lines = [f"0x{s['offset']:08x}  [{s['class']:>14}]  {s['text'][:100]}"
                 for s in interesting[:400]]
        self._emit("strings_ready", strings=info.strings)
        self.result = AnalysisRecord(
            tool="strings", operation="extract + classify",
            input_summary=os.path.basename(self.file_path),
            output_summary=f"{len(info.strings)} strings, "
                           f"{len(interesting)} interesting",
            full_output="\n".join(lines) or "(no interesting strings)")
        self._log(f"Strings: {len(info.strings)} extracted, "
                  f"{len(interesting)} interesting")
        flags = self._find_flags("\n".join(s["text"] for s in info.strings))
        if flags:
            self._log(f"🚩 flag-like strings: {flags}")

    def _op_entropy(self) -> None:
        if not self.file_path:
            self.error = "no file loaded"
            return
        data = self._load()
        ent = shannon_entropy(data)
        # per-256-byte-block entropy map for the heatmap
        block = 256
        blocks = [shannon_entropy(data[i:i + block])
                  for i in range(0, len(data), block)]
        self._emit("entropy_ready", entropy=ent, blocks=blocks)
        verdict = "possible packing/encryption" if ent > 7.5 else \
                  "normal" if ent > 4.0 else "low (structured/text)"
        self.result = AnalysisRecord(
            tool="entropy", operation="shannon entropy",
            input_summary=os.path.basename(self.file_path),
            output_summary=f"{ent:.3f} bits/byte — {verdict}",
            full_output=f"total: {ent:.3f} bits/byte\nblocks(256B): "
                        f"{[round(b, 2) for b in blocks[:64]]}\nverdict: {verdict}")
        self._log(f"Entropy {ent:.3f} — {verdict}")

    def _op_decode(self) -> None:
        if not self.value:
            self.error = "no input value"
            return
        if self.encoding == "auto":
            results = ck.auto_decode(self.value)
            out = "\n".join(f"[{enc}] {txt}" for enc, txt in results) or \
                  "(no clean decode found)"
            self.result = AnalysisRecord(
                tool="encoding", operation="auto-detect decode",
                input_summary=self.value[:80],
                output_summary=f"{len(results)} candidate decode(s)",
                full_output=out)
            self._log(f"Auto-decode: {len(results)} candidate(s)")
            for enc, txt in results:
                flags = self._find_flags(txt)
                if flags:
                    self._log(f"🚩 flag via {enc}: {flags}")
        else:
            out = ck.decode(self.value, self.encoding)
            self.result = AnalysisRecord(
                tool="encoding", operation=f"{self.encoding} decode",
                input_summary=self.value[:80], output_summary=out[:120],
                full_output=out)
            self._log(f"{self.encoding} decode → {out[:80]}")
            flags = self._find_flags(out)
            if flags:
                self._log(f"🚩 flag: {flags}")

    def _op_xor(self) -> None:
        if not self.value:
            self.error = "no input value"
            return
        data = self.value.encode("utf-8", "surrogateescape") \
            if not self.file_path else self._load()
        if self.key:
            key = self.key.encode("utf-8")
            out_bytes = ck.xor_bytes(data, key)
            out = out_bytes.decode("latin-1")
            self.result = AnalysisRecord(
                tool="xor", operation=f"xor with key {self.key!r}",
                input_summary=self.value[:60] or self.file_path,
                output_summary=out[:120], full_output=out)
            self._log(f"XOR applied → {out[:80]!r}")
            flags = self._find_flags(out)
            if flags:
                self._log(f"🚩 flag: {flags}")
            return
        # brute force single byte
        hits = ck.xor_single_byte_brute(data)
        lines = [f"key 0x{k:02x} (score {score:.2f}): {txt[:120]}"
                 for k, score, txt in hits]
        self.result = AnalysisRecord(
            tool="xor", operation="single-byte brute force",
            input_summary=(self.value[:60] or os.path.basename(self.file_path)),
            output_summary=f"{len(hits)} hit(s)",
            full_output="\n".join(lines) or "(no printable candidates)")
        self._log(f"XOR brute: {len(hits)} printable candidate(s)")
        for k, score, txt in hits:
            flags = self._find_flags(txt)
            if flags:
                self._log(f"🚩 flag with key 0x{k:02x}: {flags}")
                break

    def _op_hashid(self) -> None:
        if not self.value:
            self.error = "no input value"
            return
        ident = ck.identify_hash(self.value.strip())
        self.result = AnalysisRecord(
            tool="hash_id", operation="identify hash",
            input_summary=self.value[:80],
            output_summary=", ".join(ident), full_output="\n".join(ident))
        self._log(f"Hash ID: {', '.join(ident)}")

    def _op_caesar(self) -> None:
        if not self.value:
            self.error = "no input value"
            return
        if self.key:
            shift = int(self.key) % 26
            out = ck.caesar(self.value, shift)
        else:
            shift, out, score = ck.caesar_best(self.value)
            self._log(f"Best shift {shift} (english score {score:.2f})")
        self.result = AnalysisRecord(
            tool="crypto", operation=f"caesar shift {self.key or 'auto'}",
            input_summary=self.value[:80], output_summary=out[:120],
            full_output=out)
        flags = self._find_flags(out)
        if flags:
            self._log(f"🚩 flag: {flags}")

    def _op_vigenere(self) -> None:
        if not self.value or not self.key:
            self.error = "input and key required"
            return
        out = ck.vigenere(self.value, self.key, decrypt=True)
        self.result = AnalysisRecord(
            tool="crypto", operation=f"vigenere decrypt key={self.key!r}",
            input_summary=self.value[:80], output_summary=out[:120],
            full_output=out)
        flags = self._find_flags(out)
        if flags:
            self._log(f"🚩 flag: {flags}")

    def _op_rsa(self) -> None:
        parts = dict(p.split("=", 1) for p in self.value.split() if "=" in p)
        out = ck.analyze_rsa(parts.get("n", ""), parts.get("e", ""),
                             parts.get("c", ""), parts.get("p", ""))
        self.result = AnalysisRecord(
            tool="crypto", operation="rsa analyze",
            input_summary=self.value[:80], output_summary=out[:120],
            full_output=out)
        self._log("RSA analysis complete")

    def _op_disasm(self) -> None:
        """Optional capstone-powered disassembly (falls back gracefully)."""
        try:
            import capstone  # type: ignore
        except ImportError:
            self.error = ("capstone not installed — install with "
                          "'pip install capstone' for disassembly")
            return
        if not self.file_path:
            self.error = "no file loaded"
            return
        data = self._load()
        info = load_binary(self.file_path)
        arch = (info.architecture or "x64").lower()
        if "64" in arch or arch == "x64":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch == "x86":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch == "arm64":
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif arch == "arm":
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            self.error = f"unsupported architecture: {arch}"
            return
        code = data[:65536]
        lines = []
        for insn in list(md.disasm(code, 0x1000))[:400]:
            lines.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        out = "\n".join(lines)
        self._emit("disasm_ready", text=out)
        self.result = AnalysisRecord(
            tool="disasm", operation=f"capstone {arch}",
            input_summary=os.path.basename(self.file_path),
            output_summary=f"{len(lines)} instructions",
            full_output=out)
        self._log(f"Disassembled {len(lines)} instructions ({arch})")


def run_operation_blocking(op: str, **kw) -> AnalysisRecord:
    """Run an operation synchronously (used by the selftest)."""
    import time as _t
    q: "queue.Queue" = queue.Queue()
    eng = AnalysisEngine(op, q, **kw)
    eng.start()
    rec, err, done = None, "", False
    deadline = _t.time() + 60
    while _t.time() < deadline and not done:
        try:
            ev = q.get(timeout=0.2)
        except Exception:
            continue
        if ev["type"] == "op_done":
            rec, err, done = ev["record"], ev["error"], True
    if rec is None:
        rec = AnalysisRecord(tool=op, operation=op, success=False,
                             output_summary="timeout")
    return rec
