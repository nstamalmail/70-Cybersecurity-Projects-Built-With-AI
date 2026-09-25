"""ARP Scanner — entry point.

Default: launch the Tkinter GUI.
    python main.py

Headless mode (proves the core is GUI-free, architecture.md §5.4):
    python main.py --cli 192.168.1.0/24 [--csv out.csv] [--json out.json]
"""

from __future__ import annotations

import argparse
import sys

BANNER = (
    "ARP Scanner - authorized use only. "
    "Scan only networks you own or are permitted to assess."
)


def run_cli(cidr: str, csv_path: str | None, json_path: str | None) -> int:
    # Windows consoles are often cp1252: never let a Unicode char kill the CLI.
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

    from core import engine, exporter
    from core.models import ScanConfig

    print(BANNER)
    config = ScanConfig(cidr=cidr)
    last = {"progress": ""}

    def on_event(evt) -> None:
        if evt.kind == "start":
            print(f"Scanning {evt.value['cidr']} ({evt.value['total']} addresses) ...")
        elif evt.kind == "progress":
            info = evt.value
            line = f"  {info['done']}/{info['total']} probed"
            print("\r" + line.ljust(len(last["progress"])), end="", flush=True)
            last["progress"] = line
        elif evt.kind == "host":
            h = evt.value
            print(f"\n  [+] {h.ip:<15} {h.mac}  {h.vendor}  {h.hostname}")
        elif evt.kind == "done":
            print()
        elif evt.kind == "error":
            print(f"\n[!] {evt.value}", file=sys.stderr)

    result = engine.scan(config, event_cb=on_event)
    hosts = result.sorted_hosts()
    print(
        f"Done: {len(hosts)} host(s) in {result.duration_s:.1f}s on {result.cidr}"
    )

    if csv_path:
        exporter.export_csv(result, csv_path)
        print(f"CSV  -> {csv_path}")
    if json_path:
        exporter.export_json(result, json_path)
        print(f"JSON -> {json_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ARPScanner",
        description="ARP-based live-host discovery for Windows (SendARP engine).",
    )
    parser.add_argument("--cli", metavar="CIDR", help="headless scan of CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--csv", metavar="FILE", help="export CSV (with --cli)")
    parser.add_argument("--json", metavar="FILE", help="export JSON (with --cli)")
    args = parser.parse_args(argv)

    if args.cli:
        return run_cli(args.cli, args.csv, args.json)

    # GUI mode — import Tk layer only here so --cli stays headless.
    from ui import app as ui_app

    ui_app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
