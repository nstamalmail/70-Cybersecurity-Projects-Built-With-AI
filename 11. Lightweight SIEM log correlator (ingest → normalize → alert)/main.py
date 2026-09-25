#!/usr/bin/env python3
"""SIEM Log Correlator — entry point.

GUI mode (default) opens the desktop app. ``--headless`` runs the pipeline
without a GUI (useful for servers and tests).
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from siem.config import data_dir, load_config
from siem.notifiers import build_notifiers
from siem.pipeline import Pipeline
from siem.storage import Storage


def _safe_print(line: str) -> None:
    if sys.stdout is not None:
        try:
            print(line, flush=True)
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="SIEMCorrelator",
        description="Lightweight SIEM log correlator (ingest → normalize → alert).",
    )
    parser.add_argument("--headless", action="store_true",
                        help="run the pipeline without the GUI")
    parser.add_argument("--data-dir", default=None,
                        help="override the data directory (config, DB, logs)")
    parser.add_argument("--config", default=None,
                        help="path to a config.json file")
    args = parser.parse_args()

    data = args.data_dir or data_dir()
    os.makedirs(data, exist_ok=True)

    config = load_config(args.config or os.path.join(data, "config.json"))
    db_path = os.path.join(data, "siem.db")

    try:
        os.makedirs(os.path.join(data, "logs"), exist_ok=True)
    except OSError:
        pass

    storage = Storage(db_path, max_events_kept=int(config.get("max_events_kept", 50000)))
    on_log = _safe_print if args.headless else None

    notifiers: list = []
    if config.get("notifiers"):
        try:
            notifiers = build_notifiers(config)
        except Exception as exc:
            _safe_print(f"WARN: could not build notifiers from config: {exc}")
            notifiers = []

    pipeline = Pipeline(
        storage, config, on_log=on_log,
        alert_log_path=os.path.join(data, "logs", "alert.log"),
        notifiers=notifiers,
    )

    if args.headless:
        pipeline.start()
        _safe_print(f"Headless mode — data in {data}. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            _safe_print("Stopping…")
        finally:
            pipeline.stop()
            storage.close()
        return 0

    # GUI mode
    from siem.gui import App  # deferred import keeps headless lightweight

    app = App(pipeline, storage, config)
    pipeline.start()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app._on_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())