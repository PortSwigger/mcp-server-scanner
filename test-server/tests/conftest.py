from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn

from mcp_test_server import db
from mcp_test_server.app import build_app
from tests._helpers import _free_port


def _in_memory() -> sqlite3.Connection:
    return sqlite3.connect(":memory:")


@pytest.fixture
def fresh_db() -> Iterator[None]:
    db.set_connection_factory(_in_memory)
    yield
    db.set_connection_factory(_in_memory)


@pytest.fixture
def live_server() -> Iterator[str]:
    port = _free_port()
    config = uvicorn.Config(build_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            server.run()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        if errors:
            raise RuntimeError("uvicorn failed to start") from errors[0]
        raise RuntimeError("uvicorn did not start within 5s")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
