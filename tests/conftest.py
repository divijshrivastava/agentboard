"""Test fixtures for the agentboard server.

server/main.py opens its SQLite connection at import time from
$AGENTBOARD_DB, so each test re-imports the module against a fresh
temporary database.
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "server"))


class Clock:
    """Controllable stand-ins for time.time() and time.monotonic()."""

    def __init__(self) -> None:
        self.now = time.time()
        self.mono = time.monotonic()

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.mono += seconds


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOARD_DB", str(tmp_path / "test.db"))
    sys.modules.pop("main", None)
    module = importlib.import_module("main")
    yield module
    module._db.close()
    sys.modules.pop("main", None)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(time, "time", lambda: c.now)
    monkeypatch.setattr(time, "monotonic", lambda: c.mono)
    return c


@pytest.fixture
def client(server):
    with TestClient(server.app) as c:
        yield c
