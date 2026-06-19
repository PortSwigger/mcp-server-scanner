from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


@runtime_checkable
class AuthStrategy(Protocol):
    name: str

    def authenticate(self, request: Request) -> bool: ...

    def challenge(self) -> Response: ...


class NoAuthStrategy:
    name: str = "none"

    def authenticate(self, request: Request) -> bool:
        return True

    def challenge(self) -> Response:
        raise NotImplementedError(
            "NoAuthStrategy.authenticate always returns True; challenge() is an unreachable path."
        )


class BrokenBearerStrategy:
    name: str = "broken-bearer"

    def authenticate(self, request: Request) -> bool:
        return True

    def challenge(self) -> Response:
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
        )


# Intercepts HTTP only; WebSocket scopes bypass by design - revisit if MCP adds WebSocket transport.
class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        strategy: AuthStrategy,
        skip_paths: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self._strategy = strategy
        self._skip_paths = skip_paths

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self._is_skipped(request.url.path) or self._strategy.authenticate(request):
            return await call_next(request)
        logger.debug(
            "auth denied: %s %s via strategy=%s",
            request.method,
            request.url.path,
            self._strategy.name,
        )
        return self._strategy.challenge()

    def _is_skipped(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._skip_paths)


# TODO(auth): Three strategies to implement next, in priority order.
# Each lands as a new class in this module implementing AuthStrategy. A
# deliberately-broken BrokenBearerStrategy variant is also planned to sit
# beside these for differential testing.
#
# 1. BearerTokenStrategy - validates Authorization: Bearer <static-token> against
#    a configured token. Exercises McpActiveAuthBypassCheck on omission and a
#    future invalid-token check on garbage tokens.
#
# 2. OAuthResourceServerStrategy - validates a JWT against a configured issuer
#    and audience. This is the MCP spec's blessed path
#    (https://modelcontextprotocol.io/specification/draft/basic/authorization)
#    and enables realistic token-validation testing.
#
# 3. ApiKeyHeaderStrategy - validates a custom header (default X-API-Key)
#    against a configured value. Matches the Burp extension's
#    CustomHeaderAuthStrategy and covers a common self-hosted MCP pattern.
