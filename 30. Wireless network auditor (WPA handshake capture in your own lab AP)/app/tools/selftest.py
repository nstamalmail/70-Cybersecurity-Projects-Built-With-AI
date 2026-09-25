"""Headless self-test for WNA: builds a synthetic lab capture with a real
WPA2 handshake, then verifies the pcap parser, the verification gate, hash
conversion, the internal PSK cracker and report export.
Writes selftest_result.txt next to the executable.
"""

from __future__ import annotations

import os
import queue
import sys
import time

from app.config import get_base_dir, get_data_dir
from app.tools.capture_builder import (AP_MAC, DEFAULT_PSK, DEFAULT_SSID,
                                       STA_MAC, build_handshake_cap)
from app.utils.state import StateStore


class _Result:
    def __init__(self):
        self.checks: list = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def summary(self) -> str:
        passed = sum(1 for c in self.checks if c["ok"])
        total = len(self.checks)
        status = "PASS" if passed == total else "FAIL"
        lines = [f"WNA self-test: {status} ({passed}/{total} checks)", ""]
        for c in self.checks:
            mark = "PASS" if c["ok"] else "FAIL"
            lines.append(f"[{mark}] {c['name']}" +
                         (f" — {c['detail']}" if c.get("detail") else ""))
        return "\n".join(lines)


def _crack(result: _Result, cap_path: str, essid: str, wordlist: str,
           expect_found: bool) -> None:
    from app.core.cracker import CrackConfig, WordlistCracker
    from app.core.verifier import verify_capture

    vr = verify_capture(cap_path)
    cfg = CrackConfig(wordlist_path=wordlist, essid=essid, workers=4)
    events: "queue.Queue" = queue.Queue()
    cracker = WordlistCracker(vr, cfg, events)
    cracker.start()
    deadline = time.time() + 120
    found, done = "", False
    while time.time() < deadline and not done:
        try:
            ev = events.get(timeout=0.5)
        except Exception:
            continue
        if ev.get("type") == "crack_done":
            found, done = ev.get("found", ""), True
    if expect_found:
        result.check("internal cracker recovers PSK", found == DEFAULT_PSK,
                     f"found={found!r}")
    else:
        result.check("internal cracker exhausts wordlist", done and not found,
                     f"found={found!r}")


def run_selftest() -> int:
    result = _Result()
    base_dir = get_base_dir()
    data_dir = get_data_dir()
    result_path = os.path.join(base_dir, "selftest_result.txt")

    store = StateStore(base_dir)
    store.log_memory("self-test started (headless)")
    result.check("StateStore writes memory.md", os.path.exists(store.memory_path))

    # ---- build synthetic lab capture ---------------------------------------
    cap_path = os.path.join(data_dir, "selftest_lab.cap")
    info = build_handshake_cap(cap_path)
    result.check("synthetic handshake capture written", os.path.exists(cap_path),
                 f"{info['frames']} frames")

    # ---- pcap parser ----------------------------------------------------------
    from app.core.pcap import extract_eapol_frames
    eapols, aps, total = extract_eapol_frames(cap_path)
    key_frames = [f for f in eapols if f.is_key_frame]
    result.check("pcap parsed", total >= 5, f"{total} packets")
    result.check("beacon ESSID extracted", any(
        a.get("essid") == DEFAULT_SSID for a in aps), str(aps))
    result.check("4 EAPOL-Key frames found", len(key_frames) == 4,
                 f"{len(key_frames)}")
    msgs = [f.message for f in key_frames]
    result.check("M1..M4 classified", set(msgs) == {"M1", "M2", "M3", "M4"},
                 str(msgs))
    result.check("PMKID detected in M1", any(
        f.has_pmkid for f in key_frames if f.message == "M1"))

    # ---- verifier ---------------------------------------------------------------
    from app.core.verifier import verify_capture
    vr = verify_capture(cap_path)
    result.check("handshake complete", vr.handshake_captured
                 and vr.handshake_completeness == "complete", vr.summary())
    result.check("BSSID identified", vr.bssid == AP_MAC, vr.bssid)
    result.check("ESSID identified", vr.essid == DEFAULT_SSID, vr.essid)

    # ---- partial capture (M1+M2 only) ---------------------------------------------
    partial_path = os.path.join(data_dir, "selftest_partial.cap")
    build_handshake_cap(partial_path, include_m3_m4=False, include_pmkid=False)
    vr_partial = verify_capture(partial_path)
    result.check("partial handshake detected (not complete)",
                 (not vr_partial.handshake_captured)
                 and vr_partial.handshake_completeness == "partial",
                 vr_partial.summary())

    # ---- hash conversion --------------------------------------------------------------
    from app.core.verifier import convert_to_22000
    lines = convert_to_22000(cap_path)
    result.check("hashcat 22000 line(s) produced", len(lines) >= 1,
                 f"{len(lines)} lines")
    if lines:
        result.check("22000 line has correct prefix and MACs",
                     lines[0].startswith("WPA*01*") and
                     AP_MAC.replace(":", "").lower() in lines[0].lower())

    # ---- cracking --------------------------------------------------------------
    good_list = os.path.join(data_dir, "selftest_wordlist_good.txt")
    with open(good_list, "w", encoding="utf-8") as fh:
        fh.write("\n".join(["password", "12345678", "qwertyuiop",
                            DEFAULT_PSK, "letmein123"]) + "\n")
    _crack(result, cap_path, DEFAULT_SSID, good_list, expect_found=True)

    bad_list = os.path.join(data_dir, "selftest_wordlist_bad.txt")
    with open(bad_list, "w", encoding="utf-8") as fh:
        fh.write("\n".join(["password", "12345678", "qwertyuiop",
                            "letmein123"]) + "\n")
    _crack(result, cap_path, DEFAULT_SSID, bad_list, expect_found=False)

    # ---- report export --------------------------------------------------------------
    from app.core.report import export_all
    audit = {"id": 1, "audit_id": "selftest", "generated": "now",
             "allowlist": [AP_MAC], "adapter": "wlan0mon",
             "capture_method": "verification-only"}
    targets = [{
        "bssid": AP_MAC, "essid": DEFAULT_SSID, "channel": 6,
        "encryption": "WPA2-PSK", "handshake_captured": True,
        "handshake_completeness": "complete",
        "messages_present": ["M1", "M2", "M3", "M4"],
        "pmkid_captured": True, "hash_file": cap_path + ".hc22000",
        "crack_attempted": True, "crack_tool": "internal-py",
        "crack_result": DEFAULT_PSK, "crack_duration_seconds": 1.2,
    }]
    outdir = os.path.join(base_dir, "reports")
    paths = export_all(audit, targets, outdir)
    result.check("HTML audit report exported", os.path.exists(paths["html"]))
    result.check("CSV audit report exported", os.path.exists(paths["csv"]))
    result.check("JSON audit report exported", os.path.exists(paths["json"]))

    store.log_memory("self-test finished (verifier + cracker verified)")

    summary = result.summary()
    with open(result_path, "w", encoding="utf-8") as fh:
        fh.write(summary + "\n")

    print(summary)
    ok = all(c["ok"] for c in result.checks)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_selftest())
