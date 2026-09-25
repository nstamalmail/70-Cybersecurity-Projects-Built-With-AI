"""SentinelHIDS CLI entry point.

Usage:
    python -m hids            # launch the GUI
    python -m hids --version
"""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="SentinelHIDS",
        description="Host-based Intrusion Detection Agent "
                    "(file integrity monitoring + process monitor)",
    )
    from . import __version__
    parser.add_argument("--version", action="version",
                        version=f"SentinelHIDS {__version__}")
    parser.parse_args()

    from .gui.main_window import run_app
    run_app()


if __name__ == "__main__":
    main()
