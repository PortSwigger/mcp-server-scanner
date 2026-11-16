from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.support import TestServer, live_server

FUZZED_JSONRPC = "2.0$(printf probe)"


def _reply(server: TestServer, body: Any) -> httpx.Response:
    return server.session().post(body)


@pytest.mark.parametrize("message_id", [42, 4.5, "abc"])
def test_fuzzed_jsonrpc_reply_carries_valid_id(server: TestServer, message_id: object) -> None:
    reply = _reply(server, {"jsonrpc": FUZZED_JSONRPC, "id": message_id, "method": "ping"}).json()
    assert reply["error"]["code"] == -32600
    assert reply["id"] == message_id


@pytest.mark.parametrize("message", [
    {"jsonrpc": FUZZED_JSONRPC, "id": True, "method": "ping"},
    {"jsonrpc": FUZZED_JSONRPC, "id": {"nested": 1}, "method": "ping"},
    {"jsonrpc": FUZZED_JSONRPC, "method": "ping"},
    "not an object",
])
def test_unreadable_id_reply_carries_null_id(server: TestServer, message: object) -> None:
    reply = _reply(server, message).json()
    assert reply["error"]["code"] == -32600
    assert reply["id"] is None


def test_missing_method_reply_carries_id(server: TestServer) -> None:
    reply = _reply(server, {"jsonrpc": "2.0", "id": 9}).json()
    assert reply["error"]["code"] == -32600
    assert reply["id"] == 9


def test_missing_method_without_id_replies_with_null_id(server: TestServer) -> None:
    reply = _reply(server, {"jsonrpc": "2.0"}).json()
    assert reply["error"]["code"] == -32600
    assert reply["id"] is None


@pytest.mark.parametrize("client_reply", [
    {"jsonrpc": "2.0", "id": 3, "result": {}},
    {"jsonrpc": "2.0", "id": 3, "error": {"code": -1, "message": "no"}},
])
def test_client_reply_to_server_request_gets_no_reply(server: TestServer, client_reply: object) -> None:
    assert _reply(server, client_reply).status_code == 202


def test_legacy_sse_invalid_request_reply_carries_request_id(tmp_path: Path) -> None:
    with live_server(tmp_path) as base, httpx.Client(base_url=base, timeout=10) as client:
        with client.stream("GET", "/sse") as stream:
            lines = stream.iter_lines()
            assert next(lines) == "event: endpoint"
            endpoint = next(lines).removeprefix("data: ")
            body = {"jsonrpc": FUZZED_JSONRPC, "id": 11, "method": "ping"}
            assert client.post(endpoint, json=body).status_code == 202
            event_lines = [next(lines) for _ in range(3)]
        reply = json.loads(event_lines[2].removeprefix("data: "))
        assert reply["id"] == 11
        assert reply["error"]["code"] == -32600
