from __future__ import annotations

import sqlite3

_SCHEMA = """
CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT);
INSERT INTO notes (title, body) VALUES ('first', 'alpha'), ('second', 'beta');
CREATE TABLE secrets (owner TEXT, token TEXT);
INSERT INTO secrets VALUES ('alice', 'test-server-sql-secret');
"""


class NotesDatabase:
    def __init__(self) -> None:
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._connection.executescript(_SCHEMA)

    def rows(self, sql: str, parameters: tuple[str, ...] = ()) -> list[tuple[object, ...]]:
        return self._connection.execute(sql, parameters).fetchall()

    def has_table(self, name: str) -> bool:
        found = self.rows("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (name,))
        return bool(found)
