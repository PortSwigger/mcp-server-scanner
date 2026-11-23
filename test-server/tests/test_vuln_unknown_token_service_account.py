from __future__ import annotations

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, TestServer, tool_text

VULN = "auth_unknown_token_service_account"
ADMIN_TOOLS = {"list_users", "delete_user"}
KNOWN_USER_KEY = "bob-token"
FABRICATED_TOKEN = "fabricated-7c1e0b"
MODES = ["vulnerable", "safe"]


def _server(make_server: ServerFactory, mode: str) -> TestServer:
    return make_server(default_mode="safe", vulns={VULN: mode})


def _bearer(server: TestServer, token: str, initialize: bool = True) -> McpSession:
    return server.session({"authorization": f"Bearer {token}"}, initialize=initialize)


def _tool_names(session: McpSession) -> set[str]:
    names: set[str] = set()
    params: dict[str, str] = {}
    while True:
        result = session.result("tools/list", params)
        names |= {tool["name"] for tool in result["tools"]}
        if "nextCursor" not in result:
            return names
        params = {"cursor": result["nextCursor"]}


@pytest.mark.parametrize("mode", MODES)
def test_request_without_a_token_is_refused(make_server: ServerFactory, mode: str) -> None:
    assert _server(make_server, mode).session(initialize=False).initialize().status_code == 401


@pytest.mark.parametrize("mode", MODES)
def test_known_user_key_lists_normal_tools_only(make_server: ServerFactory, mode: str) -> None:
    names = _tool_names(_bearer(_server(make_server, mode), KNOWN_USER_KEY))
    assert "search_docs" in names
    assert names.isdisjoint(ADMIN_TOOLS)


def test_unknown_token_is_a_service_account_that_lists_admin_tools_when_vulnerable(
    make_server: ServerFactory,
) -> None:
    names = _tool_names(_bearer(_server(make_server, "vulnerable"), FABRICATED_TOKEN))
    assert names >= ADMIN_TOOLS


def test_unknown_token_lists_user_records_when_vulnerable(make_server: ServerFactory) -> None:
    result = _bearer(_server(make_server, "vulnerable"), FABRICATED_TOKEN).call_tool("list_users", {})
    assert result["isError"] is False
    assert "bob (member)" in tool_text(result)


def test_unknown_token_deletes_users_when_vulnerable(make_server: ServerFactory) -> None:
    result = _bearer(_server(make_server, "vulnerable"), FABRICATED_TOKEN).call_tool("delete_user",
                                                                                     {"username": "bob"})
    assert result["isError"] is False
    assert tool_text(result) == "user bob deleted"


def test_unknown_token_is_refused_when_safe(make_server: ServerFactory) -> None:
    response = _bearer(_server(make_server, "safe"), FABRICATED_TOKEN, initialize=False).initialize()
    assert response.status_code == 401


@pytest.mark.parametrize("mode", MODES)
def test_known_user_cannot_delete_users(make_server: ServerFactory, mode: str) -> None:
    result = _bearer(_server(make_server, mode), KNOWN_USER_KEY).call_tool("delete_user", {"username": "carol"})
    assert result["isError"] is True


@pytest.mark.parametrize("mode", MODES)
def test_deleting_an_unknown_user_is_an_error(make_server: ServerFactory, mode: str) -> None:
    result = _bearer(_server(make_server, mode), "alice-token").call_tool("delete_user", {"username": "nobody"})
    assert result["isError"] is True


def test_valid_jwt_keeps_its_own_identity_when_every_module_is_vulnerable(make_server: ServerFactory) -> None:
    server = make_server()
    session = _bearer(server, server.token())
    names = _tool_names(session)
    assert names.isdisjoint(ADMIN_TOOLS | {"whoami"})
    assert tool_text(session.call_tool("echo", {"message": "ok"})) == "ok"


def test_fabricated_token_is_still_a_service_account_when_every_module_is_vulnerable(
    make_server: ServerFactory,
) -> None:
    names = _tool_names(_bearer(make_server(), FABRICATED_TOKEN))
    assert names >= ADMIN_TOOLS
