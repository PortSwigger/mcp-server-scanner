from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_TARGET_PATH = "/mcp"
_TARGET_METHOD = "POST"


def _debug_info_result() -> dict[str, Any]:
    return {
        "server": "mcp-scanner-test-server",
        "build": "vuln-fixture",
        "uptime_seconds": 12345,
    }


def _admin_config_result() -> dict[str, Any]:
    return {
        "oauth_issuer": "http://internal.example/issuer",
        "admin_email": "ops@example.internal",
        "feature_flags": ["debug", "logs", "unsafe_eval"],
    }


def _system_list_methods_result() -> list[str]:
    return [
        "initialize",
        "tools/list",
        "tools/call",
        "debug/info",
        "admin.config",
        "internal.health",
    ]


# Standard MCP 2025-11-25 method set. Any method outside this set is rejected with
# -32601 by StrictMethodMiddleware when --hidden-methods disabled is passed.
_STANDARD_MCP_METHODS: frozenset[str] = frozenset({
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "logging/setLevel",
    "completion/complete",
    "roots/list",
    "sampling/createMessage",
})

_SUCCESS_RESULTS: dict[str, Callable[[], Any]] = {
    "debug/info": _debug_info_result,
    "admin.config": _admin_config_result,
    "system.listMethods": _system_list_methods_result,
}

_ERROR_RESULTS: dict[str, dict[str, Any]] = {
    "internal.health": {
        "code": -32001,
        "message": "Health check failed: database connection refused",
    },
}


class HiddenMethodsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not _is_target_request(scope):
            await self.app(scope, receive, send)
            return

        body = await _buffer_request_body(receive)
        intercepted = _intercept_payload(body)
        if intercepted is None:
            await self.app(scope, _replay_receive(receive, body), send)
            return

        await _send_json_response(send, intercepted)


def _is_target_request(scope: Scope) -> bool:
    return (
        scope.get("type") == "http"
        and scope.get("method") == _TARGET_METHOD
        and scope.get("path") == _TARGET_PATH
    )


async def _buffer_request_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body") or b"")
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _replay_receive(upstream: Receive, body: bytes) -> Receive:
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        # After the buffered body is replayed once, defer to the original
        # receive so the downstream app sees the same disconnect/lifespan
        # signals it would have without this middleware in the chain.
        return await upstream()

    return receive


def _intercept_payload(body: bytes) -> dict[str, Any] | None:
    method, request_id = _parse_method_and_id(body)
    if method is None:
        return None
    if method in _SUCCESS_RESULTS:
        return _success_envelope(request_id, _SUCCESS_RESULTS[method]())
    if method in _ERROR_RESULTS:
        return _error_envelope(request_id, _ERROR_RESULTS[method])
    return None


def _parse_method_and_id(body: bytes) -> tuple[str | None, Any]:
    if not body:
        return None, None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None, None
    if not isinstance(payload, dict):
        return None, None
    method = payload.get("method")
    if not isinstance(method, str):
        return None, None
    return method, payload.get("id")


def _success_envelope(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_envelope(request_id: Any, error: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


class StrictMethodMiddleware:
    """Rejects any JSON-RPC method outside the standard MCP method set with -32601.

    Used when --hidden-methods disabled is passed to reproduce the correct/patched
    server behaviour so the hidden-method check has a clean "not vulnerable" baseline.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not _is_target_request(scope):
            await self.app(scope, receive, send)
            return

        body = await _buffer_request_body(receive)
        method, request_id = _parse_method_and_id(body)
        if method is not None and method not in _STANDARD_MCP_METHODS:
            payload = _error_envelope(request_id, {
                "code": -32601,
                "message": f"Method not found: {method}",
            })
            await _send_json_response(send, payload)
            return

        await self.app(scope, _replay_receive(receive, body), send)


async def _send_json_response(send: Send, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
