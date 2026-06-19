from __future__ import annotations

from collections.abc import AsyncIterator, Collection
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from mcp_test_server import registry
from mcp_test_server.auth import AuthMiddleware, AuthStrategy, NoAuthStrategy
from mcp_test_server.hidden_methods import HiddenMethodsMiddleware, StrictMethodMiddleware
from mcp_test_server.oauth import OAuthStrategy
from mcp_test_server.request_log import RequestLogMiddleware

_SERVER_NAME = "mcp-scanner-test-server"
_SERVER_VERSION = "0.1.0-vuln-fixture"
_SERVER_INFO_ICONS = [
    {"src": "javascript:alert('serverInfo')"},
    {"src": "http://example.test/server-icon.png"},
]
_OAUTH_PUBLIC_PATHS_BASE: tuple[str, ...] = (
    "/authorize",
    "/token",
    "/revoke",
    "/.well-known/",
)
_OAUTH_PUBLIC_REGISTER: str = "/register"
_LOOPBACK_HOSTS: tuple[str, ...] = (
    "localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*",
)
_LOOPBACK_ORIGINS: tuple[str, ...] = (
    "http://localhost", "http://localhost:*",
    "http://127.0.0.1", "http://127.0.0.1:*",
    "http://[::1]", "http://[::1]:*",
)


def _oauth_skip_paths(strategy: OAuthStrategy) -> tuple[str, ...]:
    paths: tuple[str, ...] = _OAUTH_PUBLIC_PATHS_BASE
    if not strategy.dcr_strict:
        paths = (*paths, _OAUTH_PUBLIC_REGISTER)
    if strategy.test_mint_endpoint_enabled:
        paths = (*paths, "/test-only/")
    return paths


def _build_transport_security(mode: str) -> TransportSecuritySettings:
    if mode == "enabled":
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(_LOOPBACK_HOSTS),
            allowed_origins=list(_LOOPBACK_ORIGINS),
        )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def build_app(
    enabled: Collection[str] | None = None,
    disabled: Collection[str] | None = None,
    auth: AuthStrategy | None = None,
    host: str = "127.0.0.1",
    transport_security: str = "disabled",
    hidden_methods: str = "enabled",
) -> Starlette:
    # Pass transport_security explicitly so FastMCP's host-based auto-enable
    # cannot mask the vulnerable default - CVE-2025-66416 is reproduced by
    # shipping enable_dns_rebinding_protection=False regardless of bind host.
    mcp = FastMCP(
        _SERVER_NAME,
        host=host,
        transport_security=_build_transport_security(transport_security),
    )
    # FastMCP exposes no public version setter; if serverInfo.version disappears,
    # check whether FastMCP renamed/removed the _mcp_server attribute first.
    mcp._mcp_server.version = _SERVER_VERSION
    # Poison serverInfo.icons so the Unsafe Icon URI scan check sees a violation on
    # the initialize response, not just the tools/resources/prompts list responses.
    mcp._mcp_server.icons = _SERVER_INFO_ICONS
    # The --enable/--disable namespace is shared across tools and resources. An
    # integration test isolating a single resource fixture (e.g. --enable
    # read_file_rooted) legitimately registers zero tools, so the "no plugins"
    # guard must consider resources too before failing.
    registered_tools = registry.register_all(mcp, enabled=enabled, disabled=disabled)
    registered_resources = registry.register_resources_all(mcp, enabled=enabled, disabled=disabled)
    if not registered_tools and not registered_resources:
        raise RuntimeError("No plugins registered - check --enable/--disable filters")
    registry.register_prompts_all(mcp)

    streamable_http = mcp.streamable_http_app()
    sse = mcp.sse_app()

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    # Splat routes (not mount) to avoid /mcp/mcp collision. Auth attaches as outer
    # ASGI middleware below - FastMCP(auth=...) would be silently dropped here.
    app = Starlette(lifespan=lifespan, routes=[*streamable_http.routes, *sse.routes])
    strategy = auth if auth is not None else NoAuthStrategy()
    skip_paths: tuple[str, ...] = ()
    if isinstance(strategy, OAuthStrategy):
        strategy.mount_routes(app)
        skip_paths = _oauth_skip_paths(strategy)
    app.add_middleware(AuthMiddleware, strategy=strategy, skip_paths=skip_paths)
    # Sits outside AuthMiddleware so hidden methods deliberately bypass auth -
    # mirrors the real-world misconfiguration this fixture is reproducing.
    if hidden_methods == "enabled":
        app.add_middleware(HiddenMethodsMiddleware)
    else:
        # Strict mode: reject non-standard methods with -32601 (correct server behaviour).
        app.add_middleware(StrictMethodMiddleware)
    # Outermost so every request - including auth rejects and 404s from FastMCP's
    # session gate - gets logged before any inner middleware touches it.
    app.add_middleware(RequestLogMiddleware)
    return app
