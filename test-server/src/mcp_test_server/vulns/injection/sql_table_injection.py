from __future__ import annotations

import sqlite3

from mcp_test_server.vulns.injection.notes_database import NotesDatabase
from mcp_test_server.vulns.injection.single_argument_tool import InputRejected, SingleArgumentTool


class SqlTableInjection(SingleArgumentTool):
    name = "sql_table_injection"
    summary = "count_rows splices the table argument into SELECT COUNT(*) FROM {table}"
    tool_name = "count_rows"
    tool_description = "Count the rows of a table"
    argument = "table"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._database = NotesDatabase()

    async def run_vulnerable(self, value: str) -> str:
        return self._count(f"SELECT COUNT(*) FROM {value}")

    async def run_safe(self, value: str) -> str:
        if not self._database.has_table(value):
            raise InputRejected("unknown table")
        return self._count('SELECT COUNT(*) FROM "' + value.replace('"', '""') + '"')

    def _count(self, sql: str) -> str:
        try:
            return f"{self._database.rows(sql)[0][0]} rows"
        except sqlite3.Error as failure:
            raise InputRejected(f"database error: {failure}") from failure
