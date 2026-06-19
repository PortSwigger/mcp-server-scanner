from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from starlette.testclient import TestClient

from mcp_test_server.app import build_app
from tests.test_app_integration import (
    _MCP_HEADERS,
    _initialize_payload,
    _parse_event_stream_result,
    _shttp_call,
)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(build_app(), base_url="http://127.0.0.1:8000") as c:
        yield c


def _hidden_call(client: TestClient, method: str, request_id: Any = 99) -> dict[str, Any]:
    response = client.post(
        "/mcp",
        headers=_MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}},
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    return response.json()  # type: ignore[no-any-return]


def test_debug_info_returns_fake_success_payload(client: TestClient) -> None:
    payload = _hidden_call(client, "debug/info", request_id=1)

    assert payload == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "server": "mcp-scanner-test-server",
            "build": "vuln-fixture",
            "uptime_seconds": 12345,
        },
    }


def test_admin_config_returns_fake_success_payload(client: TestClient) -> None:
    payload = _hidden_call(client, "admin.config", request_id=2)

    assert payload == {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "oauth_issuer": "http://internal.example/issuer",
            "admin_email": "ops@example.internal",
            "feature_flags": ["debug", "logs", "unsafe_eval"],
        },
    }


def test_system_list_methods_returns_fake_method_list(client: TestClient) -> None:
    payload = _hidden_call(client, "system.listMethods", request_id=3)

    assert payload == {
        "jsonrpc": "2.0",
        "id": 3,
        "result": [
            "initialize",
            "tools/list",
            "tools/call",
            "debug/info",
            "admin.config",
            "internal.health",
        ],
    }


def test_internal_health_returns_custom_jsonrpc_error(client: TestClient) -> None:
    payload = _hidden_call(client, "internal.health", request_id=4)

    assert payload == {
        "jsonrpc": "2.0",
        "id": 4,
        "error": {
            "code": -32001,
            "message": "Health check failed: database connection refused",
        },
    }


def test_non_intercepted_hidden_method_falls_through_to_fastmcp(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )

    response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 5, "method": "rpc.discover", "params": {}},
        session_id=session_id,
    )

    # Non-intercepted methods reach FastMCP, which acknowledges Streamable HTTP
    # POSTs over the text/event-stream channel rather than the synchronous JSON
    # short-circuit produced by HiddenMethodsMiddleware.
    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("text/event-stream")


def test_legitimate_mcp_flow_still_works_after_middleware(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]

    notified = _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )
    assert notified.status_code in (200, 202)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    tools = _parse_event_stream_result(list_response.text)["result"]["tools"]
    tool_names = {tool["name"] for tool in tools}
    assert {"query_user", "ping_host"} <= tool_names


