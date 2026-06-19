from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "read-file-test", "version": "0.1"},
        },
    }


def _parse_event_stream_result(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: "):])
    raise AssertionError(f"No SSE data frame in body: {body!r}")


def _call(http: httpx.Client, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    response = http.post("/mcp", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    return _parse_event_stream_result(response.text)


@pytest.fixture
def session(live_server: str) -> Iterator[tuple[httpx.Client, dict[str, str]]]:
    with httpx.Client(base_url=live_server, timeout=5.0) as http:
        init_response = http.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())
        assert init_response.status_code == 200, init_response.text
        session_id = init_response.headers["mcp-session-id"]
        session_headers = {**_MCP_HEADERS, "Mcp-Session-Id": session_id}
        notified = http.post(
            "/mcp",
            headers=session_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        assert notified.status_code in (200, 202), notified.text
        yield http, session_headers


def _encoded_uri(absolute_path: Path) -> str:
    return f"file:///{quote(str(absolute_path), safe='')}"


def test_read_file_template_advertised_via_resources_templates_list(
    session: tuple[httpx.Client, dict[str, str]],
) -> None:
    http, headers = session
    result = _call(
        http,
        headers,
        {"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list", "params": {}},
    )
    templates = result["result"]["resourceTemplates"]
    uri_templates = {template["uriTemplate"] for template in templates}
    assert "file:///{path}" in uri_templates


def test_read_file_returns_canary_for_safe_path(
    session: tuple[httpx.Client, dict[str, str]], tmp_path: Path
) -> None:
    http, headers = session
    safe_file = tmp_path / "canary.txt"
    safe_file.write_text("CANARY-12345")

    result = _call(
        http,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {"uri": _encoded_uri(safe_file)},
        },
    )

    assert "error" not in result, result
    contents = result["result"]["contents"]
    assert "CANARY-12345" in contents[0]["text"]


def test_read_file_traversal_escapes_intended_directory(
    session: tuple[httpx.Client, dict[str, str]], tmp_path: Path
) -> None:
    http, headers = session
    intended_root = tmp_path / "public"
    intended_root.mkdir()
    bait_file = intended_root / "bait.txt"
    bait_file.write_text("PUBLIC-BAIT")
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("STOLEN-SECRET-XYZ")

    intended = _call(
        http,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {"uri": _encoded_uri(bait_file)},
        },
    )
    assert "error" not in intended, intended
    assert "PUBLIC-BAIT" in intended["result"]["contents"][0]["text"]

    traversal_path = f"{intended_root}/../{secret_file.name}"
    traversal_uri = f"file:///{quote(traversal_path, safe='')}"
    leaked = _call(
        http,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {"uri": traversal_uri},
        },
    )

    assert "error" not in leaked, leaked
    assert "STOLEN-SECRET-XYZ" in leaked["result"]["contents"][0]["text"]
