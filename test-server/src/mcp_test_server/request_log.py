from __future__ import annotations

import itertools
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)
_request_seq = itertools.count(1)

_INTERESTING_HEADERS = (
    b"mcp-session-id",
    b"authorization",
    b"content-type",
    b"accept",
    b"content-length",
    b"transfer-encoding",
    b"connection",
    b"upgrade",
    b"x-forwarded-for",
    b"cookie",
)
_REDACTED_HEADERS = (b"authorization", b"cookie")
_REDACTED_VALUE = "<redacted>"
_BODY_PREVIEW_BYTES = 512

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RequestLogMiddleware:
    def __init__(self, app: ASGIApp, redact_auth: bool = True) -> None:
        self.app = app
        self._redact_auth = redact_auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = f"{next(_request_seq):06d}"
        start = time.monotonic()
        client = scope.get("client") or ("?", 0)
        method = scope["method"]
        path = scope["path"]
        query = scope.get("query_string", b"").decode("latin-1", "replace")
        headers = _filter_headers(scope.get("headers", []), redact_auth=self._redact_auth)
        logger.info(
            "[%s] REQ %s:%s %s %s%s headers=%s",
            request_id,
            client[0],
            client[1],
            method,
            path,
            f"?{query}" if query else "",
            headers,
        )

        body_buf = bytearray()

        async def receive_logged() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body") or b""
                body_buf.extend(chunk)
                if not message.get("more_body", False):
                    logger.info(
                        "[%s] REQ body bytes=%d preview=%r",
                        request_id,
                        len(body_buf),
                        bytes(body_buf[:_BODY_PREVIEW_BYTES]),
                    )
            elif message["type"] == "http.disconnect":
                logger.info("[%s] REQ client disconnected before response", request_id)
            return message

        response_status: dict[str, Any] = {}
        response_bytes_sent = 0
        response_chunks = 0

        async def send_logged(message: Message) -> None:
            nonlocal response_bytes_sent, response_chunks
            if message["type"] == "http.response.start":
                response_status["status"] = message.get("status")
                response_status["headers"] = _filter_headers(
                    message.get("headers", []), redact_auth=self._redact_auth
                )
                logger.info(
                    "[%s] RES start status=%s headers=%s",
                    request_id,
                    response_status["status"],
                    response_status["headers"],
                )
            elif message["type"] == "http.response.body":
                body = message.get("body") or b""
                response_bytes_sent += len(body)
                response_chunks += 1
                if body:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    logger.info(
                        "[%s] RES chunk#%d bytes=%d at +%.0fms preview=%r",
                        request_id,
                        response_chunks,
                        len(body),
                        elapsed_ms,
                        body[:_BODY_PREVIEW_BYTES],
                    )
                if not message.get("more_body", False):
                    duration_ms = (time.monotonic() - start) * 1000
                    logger.info(
                        "[%s] RES done status=%s chunks=%d total_bytes=%d duration=%.0fms",
                        request_id,
                        response_status.get("status"),
                        response_chunks,
                        response_bytes_sent,
                        duration_ms,
                    )
            await send(message)

        try:
            await self.app(scope, receive_logged, send_logged)
        except Exception:
            duration_ms = (time.monotonic() - start) * 1000
            logger.exception(
                "[%s] app raised after %.0fms", request_id, duration_ms
            )
            raise


def _filter_headers(
    raw: list[tuple[bytes, bytes]],
    *,
    redact_auth: bool = True,
) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in raw:
        lowered = name.lower()
        if lowered not in _INTERESTING_HEADERS:
            continue
        if redact_auth and lowered in _REDACTED_HEADERS:
            out[name.decode("latin-1")] = _REDACTED_VALUE
        else:
            out[name.decode("latin-1")] = value.decode("latin-1", "replace")
    return out
