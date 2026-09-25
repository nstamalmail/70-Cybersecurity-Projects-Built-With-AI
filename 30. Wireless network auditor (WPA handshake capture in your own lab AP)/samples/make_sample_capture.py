#!/usr/bin/env python3
"""Generate a synthetic WPA2 lab capture with a complete handshake.

Run:  python samples/make_sample_capture.py [output.cap] [psk]
Defaults: data path + psk 'hunter2-but-longer'.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools.capture_builder import build_handshake_cap  # noqa: E402


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_lab_capture.cap"
    psk = sys.argv[2] if len(sys.argv) > 2 else "hunter2-but-longer"
    info = build_handshake_cap(out, psk=psk)
    print(f"wrote {info['path']} ({info['frames']} frames)")
    print(f"  ESSID: {info['ssid']}")
    print(f"  PSK:   {info['psk']}")
    print(f"  AP:    {info['ap']}   STA: {info['sta']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
