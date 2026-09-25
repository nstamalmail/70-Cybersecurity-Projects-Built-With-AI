"""Logging setup: rotating file handler plus console mirror.

File location (in priority order):
  %LOCALAPPDATA%/VlsmPlanner/logs/vlsm.log   (packaged exe, per-user)
  ./logs/vlsm.log                            (source checkout fallback)
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

APP_DIR_NAME = "VlsmPlanner"
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"


def _log_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return os.path.join(base, APP_DIR_NAME, "logs")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "logs")


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Idempotently configure the root logger; returns the app logger."""
    logger = logging.getLogger("vlsm")
    if logger.handlers:  # already configured (e.g. tests import twice)
        return logger
    logger.setLevel(level)

    log_dir = _log_dir()
    try:
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "vlsm.log"),
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)
    except OSError:
        # Logging must never crash the app — fall back to console only.
        pass

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(console)
    return logger


def log_dir_path() -> str:
    return _log_dir()