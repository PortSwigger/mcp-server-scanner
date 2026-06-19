from __future__ import annotations

import inspect
import typing

import pytest

from mcp_test_server.vulns.query_user import PLUGIN, QueryUser

pytestmark = pytest.mark.usefixtures("fresh_db")


async def test_happy_path_admin_lookup_exposes_secret_for_passive_checks() -> None:
    result = await PLUGIN.handle(username="admin")
    assert "admin@example.internal" in result
    assert "sk-live-AKIAIOSFODNN7EXAMPLE-admin" in result


async def test_happy_path_returns_user_row() -> None:
    result = await PLUGIN.handle(username="alice")
    assert "alice@example.com" in result


async def test_empty_result_returns_no_match_message() -> None:
    result = await PLUGIN.handle(username="nonexistent")
    assert result == "no matching user"


async def test_sqli_payload_leaks_multiple_rows() -> None:
    result = await PLUGIN.handle(username="' OR 1=1 --")

    seeded = {"admin", "alice", "bob", "charlie"}
    matches = {u for u in seeded if u in result}
    assert len(matches) >= 3, f"expected >=3 seeded users in SQLi output, got {matches}"


def test_handle_signature_is_typed_for_fastmcp_schema() -> None:
    sig = inspect.signature(QueryUser.handle)
    assert [p.name for p in sig.parameters.values()] == ["self", "username"]
    hints = typing.get_type_hints(QueryUser.handle)
    assert hints["username"] is str
    assert hints["return"] is str
