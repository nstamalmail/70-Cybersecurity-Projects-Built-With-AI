#!/usr/bin/env python3
"""C2 Detection Workbench — entrypoint.

Modes
-----
(default)      Launch the tkinter GUI.
--smoke        Run the full pipeline headless for every scenario and verify
               expectations (exit 0 = pass). Used by CI and by the packaged exe.
--self-test    Run the safety guard + encoder round-trips (exit 0 = pass).
--version      Print version.

Safety contract (architecture.md §0): fully offline, synthetic RFC 5737 /
reserved-TLD data only. The safety guard hard-fails the process if any
network-capable import ever enters the codebase.
"""
from __future__ import annotations

import argparse
import sys

from src import __version__
from src.safety import assert_safe, scan_for_network_imports


def _smoke() -> int:
    from src.pipeline import run_pipeline

    expectations = {
        "c2_domain_fronting": {"d1": True, "malicious": True},
        "c2_dga": {"d1": True, "dga": True},
        "ransomware_checkin": {"d1": False, "entropy": True},
        "benign_only": {"d1": False, "quiet": True},
    }
    failed: list[str] = []
    for scenario, exp in expectations.items():
        res = run_pipeline(scenario, seed=1337)
        rules = {f.rule_id for f in res.findings}
        counts = res.verdict_counts
        print(f"[{scenario}] flows={len(res.flows)} verdicts={counts} rules={sorted(rules)}")
        if exp.get("d1") and "D1" not in rules:
            failed.append(f"{scenario}: expected D1 fronting signature")
        if not exp.get("d1", False) and "D1" in rules:
            failed.append(f"{scenario}: unexpected D1 fronting signature")
        if exp.get("malicious") and counts["malicious"] == 0:
            failed.append(f"{scenario}: expected malicious verdicts")
        if exp.get("dga") and "D5" not in rules and "D3" not in rules:
            failed.append(f"{scenario}: expected D5 or D3")
        if exp.get("entropy") and "D4" not in rules:
            failed.append(f"{scenario}: expected D4 entropy")
        if exp.get("quiet") and (counts["malicious"] or counts["suspicious"]):
            failed.append(f"{scenario}: negative control should stay quiet, got {counts}")
        print(f"    pcap: {res.pcap_info.path} ({res.pcap_info.frames} frames, "
              f"sha256 {res.pcap_info.sha256[:16]}…)")
    if failed:
        print("SMOKE FAILED:")
        for f in failed:
            print(f"  - {f}")
        return 1
    print("SMOKE PASSED — all scenarios meet expectations.")
    return 0


def _self_test() -> int:
    violations = scan_for_network_imports()
    if violations:
        print("SAFETY VIOLATION:")
        for v in violations:
            print(f"  - {v}")
        return 1
    from src.simulator.encoders import layered_decode, layered_encode, shannon_entropy

    payload = b"didactic-payload-0123456789"
    for layers in (["base64"], ["xor"], ["base64", "xor"], ["rot13", "base64", "xor"]):
        enc, applied = layered_encode(payload, layers)
        if layered_decode(enc, applied) != payload:
            print(f"SELF-TEST FAILED: round-trip broke for {layers}")
            return 1
    e = shannon_entropy(bytes(range(256)) * 4)
    print(f"SAFETY OK — no network imports. Encoder round-trips OK. "
          f"Max entropy sample {e:.2f} bits/byte.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="C2DetectionWorkbench",
        description="Offline, synthetic, detection-focused C2 obfuscation demo.",
    )
    parser.add_argument("--smoke", action="store_true", help="headless pipeline verification")
    parser.add_argument("--self-test", action="store_true", help="safety guard + round-trips")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--windowed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.smoke:
        return _smoke()

    # GUI mode
    assert_safe()
    from src.gui import launch

    launch()
    return 0


if __name__ == "__main__":
    sys.exit(main())
