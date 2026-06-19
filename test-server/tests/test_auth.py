from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket

from mcp_test_server import app as app_module
from mcp_test_server.app import build_app
from mcp_test_server.auth import AuthMiddleware, AuthStrategy, BrokenBearerStrategy, NoAuthStrategy


class _StubRejector:
    name = "stub-rejector"

    def __init__(self) -> None:
        self.authenticate_calls = 0
        self.challenge_calls = 0

    def authenticate(self, request: Request) -> bool:
        self.authenticate_calls += 1
        return False

    def challenge(self) -> Response:
        self.challenge_calls += 1
        return PlainTextResponse("denied", status_code=401)


def _build_http_app(strategy: AuthStrategy, handler_flag: dict[str, bool]) -> Starlette:
    def _handler(_request: Request) -> PlainTextResponse:
        handler_flag["ran"] = True
        return PlainTextResponse("inner")

    return Starlette(
        routes=[Route("/", _handler)],
        middleware=[Middleware(AuthMiddleware, strategy=strategy)],
    )


def test_auth_strategy_protocol_runtime_checkable() -> None:
    assert isinstance(NoAuthStrategy(), AuthStrategy)
    assert not isinstance(object(), AuthStrategy)


def test_noauth_strategy_authenticates_all_requests() -> None:
    request = MagicMock(spec=Request)
    assert NoAuthStrategy().authenticate(request) is True


def test_noauth_strategy_challenge_raises() -> None:
    with pytest.raises(NotImplementedError, match="unreachable"):
        NoAuthStrategy().challenge()


def test_broken_bearer_strategy_protocol_runtime_checkable() -> None:
    assert isinstance(BrokenBearerStrategy(), AuthStrategy)


@pytest.mark.parametrize(
    "header_value",
    ["Bearer valid-looking-token", "Bearer not_a_real_token_12345", "Bearer ", "garbage", None],
)
def test_broken_bearer_strategy_authenticates_every_request(header_value: str | None) -> None:
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": header_value} if header_value is not None else {}
    assert BrokenBearerStrategy().authenticate(request) is True


def test_broken_bearer_strategy_challenge_advertises_bearer_realm() -> None:
    response = BrokenBearerStrategy().challenge()
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="mcp"'


def test_auth_middleware_forwards_when_strategy_returns_true() -> None:
    ran: dict[str, bool] = {"ran": False}
    app = _build_http_app(NoAuthStrategy(), ran)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.text == "inner"
    assert ran["ran"] is True


def test_auth_middleware_returns_challenge_when_strategy_rejects() -> None:
    rejector = _StubRejector()
    ran: dict[str, bool] = {"ran": False}
    app = _build_http_app(rejector, ran)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 401
    assert response.text == "denied"
    assert ran["ran"] is False
    assert rejector.authenticate_calls == 1
    assert rejector.challenge_calls == 1


def test_auth_middleware_passes_websockets_through_unauthenticated() -> None:
    rejector = _StubRejector()
    reached: dict[str, bool] = {"inner": False}

    async def _ws(websocket: WebSocket) -> None:
        reached["inner"] = True
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    app = Starlette(
        routes=[WebSocketRoute("/ws", _ws)],
        middleware=[Middleware(AuthMiddleware, strategy=rejector)],
    )

    with TestClient(app) as client, client.websocket_connect("/ws") as websocket:
        assert websocket.receive_text() == "hi"

    assert reached["inner"] is True
    assert rejector.authenticate_calls == 0
    assert rejector.challenge_calls == 0


def _installed_auth_strategy(app: Starlette) -> AuthStrategy:
    for middleware in app.user_middleware:
        if middleware.cls is AuthMiddleware:  # type: ignore[comparison-overlap]
            strategy = middleware.kwargs["strategy"]
            assert isinstance(strategy, AuthStrategy)
            return strategy
    raise AssertionError("AuthMiddleware not installed on app")


def test_build_app_defaults_to_noauth_strategy() -> None:
    app = build_app()
    assert isinstance(_installed_auth_strategy(app), NoAuthStrategy)


def test_build_app_accepts_custom_strategy() -> None:
    rejector = _StubRejector()
    app = build_app(auth=rejector)
    assert _installed_auth_strategy(app) is rejector
    # Sanity: re-exported symbol stays intact so future strategy additions remain routed here.
    assert app_module.build_app is build_app
