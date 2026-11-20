from __future__ import annotations

from starlette.routing import BaseRoute, Route

from mcp_test_server.oauth.authorization import AuthorizeEndpoint, ConsentDecisionEndpoint
from mcp_test_server.oauth.metadata import (
    AuthorizationServerMetadata,
    JwksEndpoint,
    ProtectedResourceMetadata,
    PublicKeyEndpoint,
)
from mcp_test_server.oauth.registration import RegistrationEndpoint
from mcp_test_server.oauth.server_context import AuthorizationServerContext
from mcp_test_server.oauth.sign_in import LoginEndpoint
from mcp_test_server.oauth.token_endpoint import TokenEndpoint


def authorization_server_routes(context: AuthorizationServerContext) -> list[BaseRoute]:
    as_metadata = AuthorizationServerMetadata(context).handle
    pr_metadata = ProtectedResourceMetadata(context).handle
    login = LoginEndpoint(context.sessions)
    return [
        Route("/.well-known/oauth-authorization-server", as_metadata),
        Route("/.well-known/openid-configuration", as_metadata),
        Route("/.well-known/oauth-protected-resource", pr_metadata),
        Route("/.well-known/oauth-protected-resource/mcp", pr_metadata),
        Route("/jwks.json", JwksEndpoint(context).handle),
        Route("/public-key.pem", PublicKeyEndpoint(context).handle),
        Route("/register", RegistrationEndpoint(context).handle, methods=["POST"]),
        Route("/authorize", AuthorizeEndpoint(context).handle, methods=["GET"]),
        Route("/authorize/consent", ConsentDecisionEndpoint(context).handle, methods=["POST"]),
        Route("/token", TokenEndpoint(context).handle, methods=["POST"]),
        Route("/login", login.show, methods=["GET"]),
        Route("/login", login.sign_in, methods=["POST"]),
    ]
