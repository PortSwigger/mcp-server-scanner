from __future__ import annotations

from dataclasses import dataclass, field

from starlette.routing import BaseRoute

from mcp_test_server.files.sandbox import FileSandbox
from mcp_test_server.http.gates import AdmissionGate
from mcp_test_server.identity.users import IdentityWeakness, UserDirectory
from mcp_test_server.oauth.consent import ConsentReflections
from mcp_test_server.oauth.credential_gate import AuthWeakness
from mcp_test_server.oauth.grants import CodeWeakness
from mcp_test_server.oauth.redirect_policy import RedirectWeakness
from mcp_test_server.oauth.refresh_policy import RefreshWeakness
from mcp_test_server.oauth.server_context import RegistrationObserver
from mcp_test_server.oauth.token_verifier import JwtWeakness
from mcp_test_server.outbound.fetcher import OutboundFetcher
from mcp_test_server.protocol.catalog import Catalog
from mcp_test_server.protocol.handlers import RequestObserver
from mcp_test_server.transport.sessions import SessionWeakness
from mcp_test_server.weakness import WeaknessSet


@dataclass(frozen=True)
class Environment:
    base_url: str
    files: FileSandbox
    fetcher: OutboundFetcher
    command_timeout_seconds: float
    allowed_hosts: tuple[str, ...]
    users: UserDirectory = field(default_factory=UserDirectory)


@dataclass
class ServerSurface:
    environment: Environment
    catalog: Catalog = field(default_factory=Catalog)
    observers: list[RequestObserver] = field(default_factory=list)
    admission_gates: list[AdmissionGate] = field(default_factory=list)
    routes: list[BaseRoute] = field(default_factory=list)
    registration_observers: list[RegistrationObserver] = field(default_factory=list)
    consent_reflections: ConsentReflections = field(default_factory=ConsentReflections)
    auth_weaknesses: WeaknessSet[AuthWeakness] = field(default_factory=WeaknessSet)
    jwt_weaknesses: WeaknessSet[JwtWeakness] = field(default_factory=WeaknessSet)
    redirect_weaknesses: WeaknessSet[RedirectWeakness] = field(default_factory=WeaknessSet)
    refresh_weaknesses: WeaknessSet[RefreshWeakness] = field(default_factory=WeaknessSet)
    session_weaknesses: WeaknessSet[SessionWeakness] = field(default_factory=WeaknessSet)
    code_weaknesses: WeaknessSet[CodeWeakness] = field(default_factory=WeaknessSet)
    identity_weaknesses: WeaknessSet[IdentityWeakness] = field(default_factory=WeaknessSet)
