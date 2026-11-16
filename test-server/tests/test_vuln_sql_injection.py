from __future__ import annotations

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, tool_text


def _session(make_server: ServerFactory, vuln: str, mode: str) -> McpSession:
    return make_server(vulns={vuln: mode}).session()


def test_count_rows_splices_the_table_name(make_server: ServerFactory) -> None:
    vulnerable = _session(make_server, "sql_table_injection", "vulnerable")
    assert tool_text(vulnerable.call_tool("count_rows", {"table": "notes"})) == "2 rows"
    assert tool_text(vulnerable.call_tool("count_rows", {"table": "notes/*q*/"})) == "2 rows"
    assert tool_text(vulnerable.call_tool("count_rows", {"table": "secrets"})) == "1 rows"
    assert vulnerable.call_tool("count_rows", {"table": "notes/q**/"})["isError"] is True


@pytest.mark.parametrize("table", ["notes/*q*/", "`notes`", "notes; DROP TABLE notes"])
def test_count_rows_safe_mode_accepts_only_existing_tables(make_server: ServerFactory, table: str) -> None:
    safe = _session(make_server, "sql_table_injection", "safe")
    assert tool_text(safe.call_tool("count_rows", {"table": "notes"})) == "2 rows"
    assert safe.call_tool("count_rows", {"table": table})["isError"] is True


def test_find_note_splices_the_title_into_a_quoted_literal(make_server: ServerFactory) -> None:
    vulnerable = _session(make_server, "sql_literal_injection", "vulnerable")
    assert tool_text(vulnerable.call_tool("find_note", {"title": "first"})) == "alpha"
    assert tool_text(vulnerable.call_tool("find_note", {"title": "first' -- q"})) == "alpha"
    assert tool_text(vulnerable.call_tool("find_note", {"title": "x' OR '1'='1"})) == "alpha\nbeta"


def test_find_note_safe_mode_binds_the_title(make_server: ServerFactory) -> None:
    safe = _session(make_server, "sql_literal_injection", "safe")
    assert tool_text(safe.call_tool("find_note", {"title": "first"})) == "alpha"
    assert tool_text(safe.call_tool("find_note", {"title": "first' -- q"})) == "no such note"
