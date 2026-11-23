from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware import Middleware

from mcp_test_server.files.sandbox import FileSandbox
from mcp_test_server.fixtures.benign import BenignCatalog
from mcp_test_server.fixtures.shared_controls import SharedIdentityControls
from mcp_test_server.http.gates import AdmissionMiddleware
from mcp_test_server.http.inspection import InspectionApi
from mcp_test_server.http.request_log import RequestLog, RequestLogMiddleware
from mcp_test_server.identity.users import IdentityWeakness, UserDirectory
from mcp_test_server.modes import ModeStore
from mcp_test_server.oauth.clients import ClientIdIssuer, ClientRegistry, RandomClientIds, SoftwareIdPrefixedClientIds
from mcp_test_server.oauth.consent import ConsentPage
from mcp_test_server.oauth.credential_gate import CredentialGate
from mcp_test_server.oauth.grants import GrantStore
from mcp_test_server.oauth.redirect_policy import RedirectPolicy
from mcp_test_server.oauth.refresh_policy import RefreshPolicy
from mcp_test_server.oauth.routes import authorization_server_routes
from mcp_test_server.oauth.server_context import AuthorizationServerContext
from mcp_test_server.oauth.sign_in import SignedInSessions
from mcp_test_server.oauth.signer import JwtSigner
from mcp_test_server.oauth.token_verifier import JwtWeakness, TokenVerifier
from mcp_test_server.outbound.fetcher import HttpGetter, HttpxGetter, OutboundFetcher
from mcp_test_server.protocol.dispatcher import Dispatcher
from mcp_test_server.protocol.families import FamilySwitches
from mcp_test_server.protocol.method_table import method_handlers
from mcp_test_server.protocol.versions import ProtocolVersions
from mcp_test_server.settings import ServerSettings
from mcp_test_server.surface import Environment, ServerSurface
from mcp_test_server.transport.routes import GUARDED_PATHS, STREAMABLE_HTTP_PATH, transport_routes
from mcp_test_server.transport.session_binding import SessionBinding
from mcp_test_server.transport.sessions import SessionStore
from mcp_test_server.vulns import registry
from mcp_test_server.weakness import WeaknessSet


def build_app(settings: ServerSettings) -> Starlette:
    return ServerAssembly(settings).application()


class ServerAssembly:
    def __init__(self, settings: ServerSettings, getter: HttpGetter | None = None) -> None:
        self._settings = settings
        self._validate_vuln_names()
        self.modes = ModeStore(settings.default_mode, settings.vulns)
        self.families = FamilySwitches(settings.disabled_families)
        self.request_log = RequestLog(settings.request_log)
        self.fetcher = OutboundFetcher(getter or HttpxGetter(settings.fetch_timeout))
        self.files = FileSandbox.create(settings.files_dir)
        self.identity_weaknesses: WeaknessSet[IdentityWeakness] = WeaknessSet()
        self.jwt_weaknesses: WeaknessSet[JwtWeakness] = WeaknessSet()
        self.signer = JwtSigner(settings.base_url, settings.base_url + STREAMABLE_HTTP_PATH)
        self.verifier = TokenVerifier(self.signer, self.jwt_weaknesses)
        self.users = UserDirectory(weaknesses=self.identity_weaknesses, recognised_elsewhere=self.verifier.accepts)
        self.surface = ServerSurface(self._environment(), jwt_weaknesses=self.jwt_weaknesses,
                                     identity_weaknesses=self.identity_weaknesses)
        self.vulnerabilities = registry.instantiate(self.modes)
        self._contribute_all()

    def application(self) -> Starlette:
        versions = ProtocolVersions(self._settings.protocol_versions)
        dispatcher = Dispatcher(
            method_handlers(self.surface.catalog, self.families, self._settings.page_size, versions),
            self.families,
            self.surface.observers,
        )
        sessions = SessionStore(self._settings.sessions, self.surface.session_weaknesses)
        routes = [
            *transport_routes(dispatcher, sessions, self._session_binding(), self._settings.response_mode,
                              self.families, versions, self.surface.catalog.tools),
            *authorization_server_routes(self._oauth_context()),
            *self.surface.routes,
            *self._inspection().routes(),
        ]
        middleware = [
            Middleware(RequestLogMiddleware, log=self.request_log),
            Middleware(AdmissionMiddleware, gates=[*self.surface.admission_gates, self._credential_gate()],
                       guarded_paths=GUARDED_PATHS),
        ]
        return Starlette(routes=routes, middleware=middleware)

    def _validate_vuln_names(self) -> None:
        unknown = set(self._settings.vulns) - registry.vulnerability_names()
        if unknown:
            raise ValueError(f"Unknown vulnerabilities: {', '.join(sorted(unknown))}")

    def _environment(self) -> Environment:
        return Environment(
            base_url=self._settings.base_url,
            files=self.files,
            fetcher=self.fetcher,
            command_timeout_seconds=self._settings.command_timeout,
            allowed_hosts=self._settings.allowed_hosts,
            users=self.users,
        )

    def _contribute_all(self) -> None:
        BenignCatalog().contribute(self.surface)
        SharedIdentityControls().contribute(self.surface)
        for vulnerability in self.vulnerabilities:
            vulnerability.contribute(self.surface)

    def _credential_gate(self) -> CredentialGate:
        return CredentialGate(
            self.verifier,
            self.users,
            self.surface.auth_weaknesses,
            f"{self._settings.base_url}/.well-known/oauth-protected-resource{STREAMABLE_HTTP_PATH}",
        )

    def _session_binding(self) -> SessionBinding:
        return SessionBinding(self.users, self.surface.session_weaknesses)

    def _oauth_context(self) -> AuthorizationServerContext:
        return AuthorizationServerContext(
            base_url=self._settings.base_url,
            signer=self.signer,
            clients=ClientRegistry(self._client_ids()),
            grants=GrantStore(self.surface.code_weaknesses),
            redirect_policy=RedirectPolicy(self.surface.redirect_weaknesses),
            refresh_policy=RefreshPolicy(self.surface.refresh_weaknesses),
            consent_page=ConsentPage(self.surface.consent_reflections),
            consent_mode=self._settings.consent,
            consent_memory=self._settings.consent.memory(),
            sessions=SignedInSessions(),
            registration_observers=self.surface.registration_observers,
        )

    def _client_ids(self) -> ClientIdIssuer:
        return SoftwareIdPrefixedClientIds() if self._settings.consent.needs_sign_in else RandomClientIds()

    def _inspection(self) -> InspectionApi:
        return InspectionApi(self.request_log, self.fetcher, self.modes, self.vulnerabilities, self.signer,
                             self._settings_view())

    def _settings_view(self) -> dict[str, object]:
        return {
            "base_url": self._settings.base_url,
            "files_root": str(self.files.root),
            "disabled_families": self.families.disabled(),
            "page_size": self._settings.page_size,
            "sessions": self._settings.sessions.value,
            "response_mode": self._settings.response_mode.value,
            "consent": self._settings.consent.value,
            "allowed_hosts": list(self._settings.allowed_hosts),
            "protocol_versions": list(self._settings.protocol_versions),
        }

