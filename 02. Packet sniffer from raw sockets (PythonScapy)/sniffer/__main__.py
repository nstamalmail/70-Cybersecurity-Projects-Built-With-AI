"""Allow `python -m sniffer` to launch the same CLI as main.py."""

import sys
from pathlib import Path

# ensure project root is importable when run from an arbitrary cwd
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
