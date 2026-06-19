from __future__ import annotations

import sqlite3
from collections.abc import Callable

_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    secret TEXT
)
"""

_SEED_ROWS = (
    ("admin", "admin@example.internal", "sk-live-AKIAIOSFODNN7EXAMPLE-admin"),
    ("alice", "alice@example.com", "alice-personal-note"),
    ("bob", "bob@example.com", "bob-remembers-birthdays"),
    ("charlie", "charlie@example.com", "charlie-likes-coffee"),
)

def _default_factory() -> sqlite3.Connection:
    return sqlite3.connect(":memory:")


_connection: sqlite3.Connection | None = None
_factory: Callable[[], sqlite3.Connection] = _default_factory


def set_connection_factory(factory: Callable[[], sqlite3.Connection]) -> None:
    global _factory, _connection
    _factory = factory
    _connection = None


def conn() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        _connection = _factory()
        _seed(_connection)
    return _connection


def reset() -> None:
    connection = conn()
    connection.execute("DROP TABLE IF EXISTS users")
    _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executescript(_SCHEMA)
    connection.executemany(
        "INSERT INTO users (username, email, secret) VALUES (?, ?, ?)",
        _SEED_ROWS,
    )
    connection.commit()
