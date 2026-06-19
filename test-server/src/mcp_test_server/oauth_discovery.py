from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NamedTuple

from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

if TYPE_CHECKING:
    from mcp.server.auth.provider import OAuthAuthorizationServerProvider

_AS_OVERRIDABLE_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "revocation_endpoint",
    "jwks_uri",
)


PRM_WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"
AS_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"


class _ModeCapabilities(NamedTuple):
    emits_resource_metadata_header: bool
    serves_prm_well_known: bool
    serves_as_well_known: bool


class DiscoveryMode(StrEnum):
    FULL = "full"
    HEADER_ONLY = "header-only"
    PRM_ONLY = "prm-only"
    AS_ONLY = "as-only"
    NONE = "none"

    @property
    def emits_resource_metadata_header(self) -> bool:
        return _MODE_TABLE[self].emits_resource_metadata_header

    @property
    def serves_prm_well_known(self) -> bool:
        return _MODE_TABLE[self].serves_prm_well_known

    @property
    def serves_as_well_known(self) -> bool:
        return _MODE_TABLE[self].serves_as_well_known


_MODE_TABLE: dict[DiscoveryMode, _ModeCapabilities] = {
    DiscoveryMode.FULL:        _ModeCapabilities(True,  True,  True),
    DiscoveryMode.HEADER_ONLY: _ModeCapabilities(True,  False, False),
    DiscoveryMode.PRM_ONLY:    _ModeCapabilities(False, True,  False),
    DiscoveryMode.AS_ONLY:     _ModeCapabilities(False, False, True),
    DiscoveryMode.NONE:        _ModeCapabilities(False, False, False),
}


@dataclass(frozen=True)
class DiscoveryRouteSet:
    mode: DiscoveryMode
    provider: "OAuthAuthorizationServerProvider"
    issuer_url: str
    audience: str
    issuer_override: str | None = None

    def include_resource_metadata_in_challenge(self) -> bool:
        return self.mode.emits_resource_metadata_header

    def routes(self) -> list[Route]:
        routes: list[Route] = []
        if self.mode.serves_prm_well_known:
            routes.append(self._build_prm_route())
        if self.mode.serves_as_well_known:
            routes.append(self._build_as_well_known_route())
        return routes

    def _build_prm_route(self) -> Route:
        return Route(
            PRM_WELL_KNOWN_PATH,
            endpoint=self._handle_protected_resource_metadata,
            methods=["GET"],
        )

    def _build_as_well_known_route(self) -> Route:
        if self.issuer_override:
            return Route(
                AS_WELL_KNOWN_PATH,
                endpoint=self._handle_overridden_as_metadata,
                methods=["GET"],
            )
        metadata = build_metadata(
            issuer_url=AnyHttpUrl(self.issuer_url),
            service_documentation_url=None,
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(),
        )
        return Route(
            AS_WELL_KNOWN_PATH,
            endpoint=MetadataHandler(metadata).handle,
            methods=["GET"],
        )

    async def _handle_overridden_as_metadata(self, _request: Request) -> Response:
        override = self.issuer_override or self.issuer_url
        real_metadata = build_metadata(
            issuer_url=AnyHttpUrl(self.issuer_url),
            service_documentation_url=None,
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(),
        )
        doc: dict[str, Any] = real_metadata.model_dump(mode="json", exclude_none=True)
        doc = _apply_issuer_override(doc, self.issuer_url, override)
        return JSONResponse(doc)

    async def _handle_protected_resource_metadata(self, _request: Request) -> Response:
        metadata = ProtectedResourceMetadata(
            resource=AnyHttpUrl(self.audience),
            authorization_servers=[AnyHttpUrl(self.issuer_url)],
            jwks_uri=AnyHttpUrl(f"{self.issuer_url.rstrip('/')}/.well-known/jwks.json"),
            bearer_methods_supported=["header"],
        )
        return JSONResponse(metadata.model_dump(mode="json", exclude_none=True))


def _apply_issuer_override(doc: dict[str, Any], real_issuer: str, override: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in doc.items():
        if isinstance(value, str) and value.startswith(real_issuer):
            result[key] = override + value[len(real_issuer):]
        else:
            result[key] = value
    return result
