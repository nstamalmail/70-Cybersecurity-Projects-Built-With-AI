"""Shared fixtures for headless core/engine tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from hids.core.config import Config
from hids.core.database import Database
from hids.core.events import EventBus


@pytest.fixture
def env(tmp_path):
    config = Config(tmp_path)
    db = Database(tmp_path)
    bus = EventBus()
    return config, db, bus
