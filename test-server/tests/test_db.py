from __future__ import annotations

import re

import pytest

from mcp_test_server import db

pytestmark = pytest.mark.usefixtures("fresh_db")

_LEAKY_SECRET_PATTERN = re.compile(r"sk-[A-Za-z0-9-]+")


def _usernames() -> set[str]:
    rows = db.conn().execute("SELECT username FROM users").fetchall()
    return {row[0] for row in rows}


def test_conn_returns_working_connection() -> None:
    result = db.conn().execute("SELECT 1").fetchone()
    assert result == (1,)


def test_seed_fixtures_present() -> None:
    assert _usernames() == {"admin", "alice", "bob", "charlie"}


def test_admin_secret_is_leaky() -> None:
    row = db.conn().execute("SELECT secret FROM users WHERE username = ?", ("admin",)).fetchone()
    assert row is not None
    assert _LEAKY_SECRET_PATTERN.search(row[0])


def test_reset_reseeds_clean_state() -> None:
    db.conn().execute("DELETE FROM users WHERE username = ?", ("alice",))
    db.conn().commit()
    assert "alice" not in _usernames()

    db.reset()

    assert _usernames() == {"admin", "alice", "bob", "charlie"}


def test_conn_is_singleton() -> None:
    assert db.conn() is db.conn()
