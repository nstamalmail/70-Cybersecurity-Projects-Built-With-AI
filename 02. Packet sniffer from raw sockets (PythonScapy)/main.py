#!/usr/bin/env python3
"""PacketSniffer — GUI packet sniffer on raw sockets.

Usage:
    python main.py                    # launch GUI
    python main.py --list-interfaces  # enumerate capture interfaces
    python main.py --headless --duration 30 --out capture.pcap
    python main.py capture.pcap       # open a pcap in the GUI

Ethical use: capture only on networks you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="PacketSniffer",
        description="GUI packet sniffer built on raw sockets (passive analysis only).")
    p.add_argument("pcap", nargs="?", help="optional .pcap file to open in the GUI")
    p.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    p.add_argument("--interface", "-i", default="", help="interface name or local IP to bind")
    p.add_argument("--headless", action="store_true", help="capture without GUI (CLI capture)")
    p.add_argument("--duration", type=float, default=30.0, help="headless capture seconds")
    p.add_argument("--out", "-o", default="capture.pcap", help="headless output pcap path")
    p.add_argument("--bpf", default="", help="reserved for kernel BPF (not yet wired)")
    p.add_argument("--yes", "-y", action="store_true", help="accept legal notice non-interactively")
    p.add_argument("--version", action="version", version="PacketSniffer 1.0.0")
    return p


def headless_capture(args) -> int:
    import time

    from sniffer.capture import PcapWriter, RawSocketEngine, SnifferConfig
    from sniffer.dissectors import dissect
    from sniffer.models import Packet

    config = SnifferConfig(interface=args.interface, name=args.interface or "default")
    engine = RawSocketEngine(config)
    writer = PcapWriter(args.out)
    deadline = time.time() + args.duration
    count = 0

    def on_error(msg: str) -> None:
        print(f"[!] {msg}", file=sys.stderr)

    engine.on_error(on_error)

    def loop() -> None:
        nonlocal count
        engine.open()
        print(f"[*] capturing on '{config.name}' for {args.duration:.0f}s → {args.out}")
        try:
            while time.time() < deadline and not engine.stop_event.is_set():
                got = engine.read_packet()
                if got is None:
                    continue
                ts, raw, orig_len = got
                pkt = dissect(Packet(number=count + 1, timestamp=ts, raw=raw, orig_len=orig_len),
                              link_layer=config.link_layer)
                writer.write_packet(ts, raw, orig_len)
                count += 1
                if count % 100 == 0:
                    print(f"    {count} packets…")
        finally:
            engine.close()
            writer.close()

    try:
        loop()
    except PermissionError as exc:
        print(f"[!] permission denied: {exc}", file=sys.stderr)
        print("    Windows: run from an elevated prompt. Linux: sudo / setcap cap_net_raw+ep.",
              file=sys.stderr)
        return 2
    print(f"[+] wrote {count} packets to {args.out}")
    return 0


def main() -> int:
    args = build_parser().parse_args()

    if args.list_interfaces:
        from sniffer.capture import list_interfaces
        for i in list_interfaces():
            ip = f"  ip={i['ip']}" if i.get("ip") else ""
            print(f"{i['name']}  ({i.get('desc', '')}){ip}")
        return 0

    if args.headless:
        if not args.yes:
            print("NOTE: sniffing networks you do not own may be illegal. "
                  "Pass --yes to accept responsibility.")
            return 1
        return headless_capture(args)

    # GUI path
    import tkinter as tk

    from sniffer.gui.app import MainWindow

    root = tk.Tk()
    try:
        app = MainWindow(root, skip_notice=args.yes)
    except Exception:
        raise
    if args.pcap:
        root.after(200, lambda: _open_pcap(app, args.pcap))
    root.mainloop()
    return 0


def _open_pcap(app, path: str) -> None:
    """Open a pcap after the GUI is up (used by `python main.py file.pcap`)."""
    try:
        app.open_pcap_path(path)
    except Exception as exc:
        print(f"[!] cannot open {path}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
