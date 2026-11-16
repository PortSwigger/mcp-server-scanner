from __future__ import annotations

import sqlite3

from mcp_test_server.vulns.injection.notes_database import NotesDatabase
from mcp_test_server.vulns.injection.single_argument_tool import InputRejected, SingleArgumentTool


class SqlLiteralInjection(SingleArgumentTool):
    name = "sql_literal_injection"
    summary = "find_note splices the title argument into a single-quoted SQL literal"
    tool_name = "find_note"
    tool_description = "Return the body of the note with this title"
    argument = "title"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._database = NotesDatabase()

    async def run_vulnerable(self, value: str) -> str:
        return self._bodies(f"SELECT body FROM notes WHERE title = '{value}'", ())

    async def run_safe(self, value: str) -> str:
        return self._bodies("SELECT body FROM notes WHERE title = ?", (value,))

    def _bodies(self, sql: str, parameters: tuple[str, ...]) -> str:
        try:
            rows = self._database.rows(sql, parameters)
        except sqlite3.Error as failure:
            raise InputRejected(f"database error: {failure}") from failure
        return "\n".join(str(row[0]) for row in rows) or "no such note"
