from __future__ import annotations

import base64
import html
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthToken,
)
from pydantic import AnyHttpUrl, AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from mcp_test_server.oauth_discovery import (
    AS_WELL_KNOWN_PATH,
    DiscoveryMode,
    DiscoveryRouteSet,
)

logger = logging.getLogger(__name__)

# A login bounce sends /authorize CROSS-ORIGIN to this sign-in host before consent. The scanner
# never connects here (its check refuses cross-origin hops); it only unwraps the AS-origin consent
# URL embedded in a query param, so a non-resolvable placeholder host is correct and safe.
SIGNIN_URL = "https://signin.idp.test/signin"

# Consent-page rendering modes. Each unsafe mode interpolates the attacker-controlled DCR
# client_name RAW into served HTML — a genuine bug — but in a DIFFERENT shape, so the check is
# exercised against a bug CLASS rather than one server's fingerprint:
#   none             legacy 302 redirect, no consent page
#   safe             HTML-escapes client_name (no bug)
#   vulnerable       raw reflection inside a <script> island, direct 200 (no bounce)
#   bounce-loopback  cross-origin login bounce (postSignUp param) + raw reflection ONLY for loopback
#   body-https       direct 200, raw reflection in a plain HTML <body> element (not a <script> island)
#   attribute        direct 200, raw reflection inside an HTML attribute value (href="...")
#   bounce-altparam  login bounce carrying the consent URL in a NON-postSignUp param (goto=)
#   inverse-trust    raw reflection ONLY for the https redirect (inverse of the loopback gate)
#   comment-only     marker survives ONLY inside an HTML comment (non-executable; must NOT fire)
CONSENT_PAGE_MODES = (
    "none",
    "safe",
    "vulnerable",
    "bounce-loopback",
    "body-https",
    "attribute",
    "bounce-altparam",
    "inverse-trust",
    "comment-only",
)
_BOUNCING_MODES = ("bounce-loopback", "bounce-altparam")

ACCESS_TOKEN_LIFETIME_SECONDS = 60
REFRESH_TOKEN_LIFETIME_SECONDS = 3600
AUTHORIZATION_CODE_LIFETIME_SECONDS = 300
JWT_ALGORITHM = "RS256"
JWT_KEY_ID = "mcp-test-server-1"


@dataclass(frozen=True)
class VerifyOptions:
    skip_signature_check: bool = False
    accept_alg_none: bool = False
    skip_audience_check: bool = False
    skip_issuer_check: bool = False
    skip_expiry_check: bool = False


@dataclass
class JwtSigner:
    issuer: str
    audience: str
    private_key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    def sign(self, *, subject: str, scopes: list[str], expires_in: int) -> str:
        now = int(time.time())
        return self.sign_claims(
            {
                "iss": self.issuer,
                "sub": subject,
                "aud": self.audience,
                "iat": now,
                "exp": now + expires_in,
                "scope": " ".join(scopes),
            }
        )

    def sign_claims(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims,
            self._private_key_pem(),
            algorithm=JWT_ALGORITHM,
            headers={"kid": JWT_KEY_ID},
        )

    def verify(
        self, token: str, options: VerifyOptions = VerifyOptions()
    ) -> dict[str, Any]:
        if options.accept_alg_none and _is_alg_none(token):
            # Vulnerable mode by design: bypasses signature and all claim checks (aud/iss/exp).
            return _decode_unsigned_claims(token)
        decode_kwargs = self._build_decode_kwargs(options)
        return jwt.decode(token, self._public_key_pem(), **decode_kwargs)

    def _build_decode_kwargs(self, options: VerifyOptions) -> dict[str, Any]:
        verify_options: dict[str, bool] = {}
        kwargs: dict[str, Any] = {"algorithms": [JWT_ALGORITHM]}
        if options.skip_signature_check:
            verify_options["verify_signature"] = False
            kwargs["algorithms"] = [JWT_ALGORITHM, "none"]
        if options.skip_audience_check:
            verify_options["verify_aud"] = False
        else:
            kwargs["audience"] = self.audience
        if options.skip_issuer_check:
            verify_options["verify_iss"] = False
        else:
            kwargs["issuer"] = self.issuer
        if options.skip_expiry_check:
            verify_options["verify_exp"] = False
        if verify_options:
            kwargs["options"] = verify_options
        return kwargs

    def jwks(self) -> dict[str, Any]:
        numbers = self.public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": JWT_ALGORITHM,
                    "kid": JWT_KEY_ID,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }

    def _private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def _b64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode_segment(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _is_alg_none(token: str) -> bool:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        return False
    return header.get("alg", "").lower() == "none"


def _decode_unsigned_claims(token: str) -> dict[str, Any]:
    segments = token.split(".")
    if len(segments) < 2:
        raise jwt.InvalidTokenError("malformed token: missing claims segment")
    claims = json.loads(_b64url_decode_segment(segments[1]))
    if not isinstance(claims, dict):
        raise jwt.InvalidTokenError("alg:none payload must be a JSON object")
    return claims


class InMemoryOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    def __init__(self, signer: JwtSigner) -> None:
        self._signer = signer
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    def add_preregistered_client(self, client: OAuthClientInformationFull) -> None:
        if client.client_id is None:
            raise ValueError("preregistered client must have client_id")
        self._clients[client.client_id] = client

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("register_client requires client_id to be set by handler")
        self._clients[client_info.client_id] = client_info

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        code = AuthorizationCode(
            code=f"code_{secrets.token_urlsafe(24)}",
            scopes=params.scopes or [],
            expires_at=time.time() + AUTHORIZATION_CODE_LIFETIME_SECONDS,
            client_id=client.client_id or "",
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        self._codes[code.code] = code
        return construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self._codes.get(authorization_code)

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return self._issue_tokens(client, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return self._refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
        return self._issue_tokens(client, scopes or refresh_token.scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        return self._access_tokens.get(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        else:
            self._refresh_tokens.pop(token.token, None)

    def _issue_tokens(
        self, client: OAuthClientInformationFull, scopes: list[str]
    ) -> OAuthToken:
        client_id = client.client_id or ""
        access_jwt = self._signer.sign(
            subject=client_id,
            scopes=scopes,
            expires_in=ACCESS_TOKEN_LIFETIME_SECONDS,
        )
        refresh_value = f"refresh_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        self._access_tokens[access_jwt] = AccessToken(
            token=access_jwt,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + ACCESS_TOKEN_LIFETIME_SECONDS,
        )
        self._refresh_tokens[refresh_value] = RefreshToken(
            token=refresh_value,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + REFRESH_TOKEN_LIFETIME_SECONDS,
        )
        return OAuthToken(
            access_token=access_jwt,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME_SECONDS,
            refresh_token=refresh_value,
            scope=" ".join(scopes) if scopes else None,
        )


def _is_url_parseable(value: str) -> bool:
    try:
        AnyUrl(value)
        return True
    except ValueError:
        return False


def _is_unsafe_redirect(redirect_uri: str) -> bool:
    lowered = redirect_uri.strip().lower()
    if lowered.startswith(("javascript:", "data:", "http://")):
        return True
    if ".." in redirect_uri:
        return True
    # The scanner registers a wildcard host then authorizes a different concrete subdomain;
    # a hardened AS treats any *.attacker.example target as not allow-listed.
    return "attacker.example" in lowered


def _is_loopback_redirect(redirect_uri: str) -> bool:
    # RFC 8252 loopback: http://127.0.0.1, http://localhost, http://[::1] (any port). Mirrors the
    # isTrusted gate that reflects client_name on the consent page only for loopback clients.
    lowered = redirect_uri.strip().lower()
    return (
        lowered.startswith("http://127.0.0.1")
        or lowered.startswith("http://localhost")
        or lowered.startswith("http://[::1]")
    )


def _build_preregistered_client(spec: dict[str, Any]) -> OAuthClientInformationFull:
    redirect_uris: list[str] = spec.get("redirect_uris") or ["http://localhost:33418/callback"]
    return OAuthClientInformationFull(
        client_id=spec["client_id"],
        client_secret=spec.get("client_secret"),
        redirect_uris=[AnyUrl(uri) for uri in redirect_uris],
        token_endpoint_auth_method="client_secret_post",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
    )


def _reflecting_script_island_html(client_name: str) -> str:
    # Script-island fingerprint: reflect client_name UNESCAPED inside a <script> JSON island, no CSP.
    return (
        "<!doctype html><html><head><title>Authorize</title>"
        "<script>window.__client = {\"client_name\": \"" + client_name + "\"};</script>"
        "</head><body>"
        "<h1>Authorize application</h1>"
        "<form method=\"post\"><button>Allow</button></form>"
        "</body></html>"
    )


def _reflecting_body_html(client_name: str) -> str:
    # Reflect client_name UNESCAPED into a plain HTML body element (an <h1>) — NOT a <script>
    # island. Same bug class, different sink: tag-parsing breakout in HTML body context, no CSP.
    return (
        "<!doctype html><html><head><title>Authorize</title></head><body>"
        f"<h1>Authorize {client_name}</h1>"
        "<form method=\"post\"><button>Allow</button></form>"
        "</body></html>"
    )


def _reflecting_attribute_html(client_name: str) -> str:
    # Reflect client_name UNESCAPED inside an HTML attribute value (href="..."). The </script>
    # and angle brackets in the canary break out of the attribute into tag-parsing context, no CSP.
    return (
        "<!doctype html><html><head><title>Authorize</title></head><body>"
        f"<a href=\"/grant?app={client_name}\">Allow this application</a>"
        "<form method=\"post\"><button>Allow</button></form>"
        "</body></html>"
    )


def _comment_only_html(client_name: str) -> str:
    # NOT a bug: client_name is reflected RAW but only inside an HTML comment that is never closed
    # before it, so the browser never tag-parses the marker. The check's comment guard must treat
    # this as non-executable and raise nothing.
    return (
        "<!doctype html><html><head><title>Authorize</title></head><body>"
        f"<!-- consent for client: {client_name} -->"
        "<h1>Authorize application</h1>"
        "<form method=\"post\"><button>Allow</button></form>"
        "</body></html>"
    )


class OAuthStrategy:
    name: str = "oauth"

    def __init__(
        self,
        issuer: str,
        audience: str,
        allow_dcr: bool,
        preregistered_clients: list[dict[str, Any]] | None = None,
        discovery_mode: DiscoveryMode = DiscoveryMode.FULL,
        skip_signature_check: bool = False,
        accept_alg_none: bool = False,
        skip_audience_check: bool = False,
        skip_issuer_check: bool = False,
        skip_expiry_check: bool = False,
        dcr_strict: bool = False,
        authorize_reject_unsafe: bool = False,
        issuer_override: str | None = None,
        test_mint_endpoint: bool = False,
        consent_page: str = "none",
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._allow_dcr = allow_dcr
        self._dcr_strict = dcr_strict
        self._authorize_reject_unsafe = authorize_reject_unsafe
        self._test_mint_endpoint = test_mint_endpoint
        self._consent_page = consent_page
        self._client_names: dict[str, str] = {}
        self._signer = JwtSigner(issuer=self._issuer, audience=self._audience)
        self._verify_options = VerifyOptions(
            skip_signature_check=skip_signature_check,
            accept_alg_none=accept_alg_none,
            skip_audience_check=skip_audience_check,
            skip_issuer_check=skip_issuer_check,
            skip_expiry_check=skip_expiry_check,
        )
        self._provider = InMemoryOAuthProvider(self._signer)
        for spec in preregistered_clients or []:
            self._provider.add_preregistered_client(_build_preregistered_client(spec))
        self._route_set = DiscoveryRouteSet(
            mode=discovery_mode,
            provider=self._provider,
            issuer_url=self._issuer,
            audience=self._audience,
            issuer_override=issuer_override.rstrip("/") if issuer_override else None,
        )

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def signer(self) -> JwtSigner:
        return self._signer

    @property
    def provider(self) -> InMemoryOAuthProvider:
        return self._provider

    @property
    def dcr_strict(self) -> bool:
        return self._dcr_strict

    @property
    def test_mint_endpoint_enabled(self) -> bool:
        return self._test_mint_endpoint

    def authenticate(self, request: Request) -> bool:
        token = self._extract_bearer_token(request)
        if token is None:
            return False
        try:
            self._signer.verify(token, self._verify_options)
        except jwt.InvalidTokenError as exc:
            logger.debug("oauth: token rejected: %s", exc)
            return False
        return True

    def challenge(self) -> Response:
        challenge_value = 'Bearer realm="mcp"'
        if self._route_set.include_resource_metadata_in_challenge():
            resource_metadata_url = f"{self._issuer}/.well-known/oauth-protected-resource"
            challenge_value = f'{challenge_value}, resource_metadata="{resource_metadata_url}"'
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": challenge_value},
        )

    def mount_routes(self, app: Starlette) -> None:
        sdk_routes = create_auth_routes(
            provider=self._provider,
            issuer_url=AnyHttpUrl(self._issuer),
            client_registration_options=ClientRegistrationOptions(enabled=self._allow_dcr),
        )
        protocol_routes = [
            r for r in sdk_routes
            if r.path != AS_WELL_KNOWN_PATH and not self._should_replace_route(r)
        ]
        app.router.routes.extend(protocol_routes)
        if self._should_install_permissive_register():
            app.router.routes.append(
                Route(
                    "/register",
                    endpoint=self._permissive_register_endpoint,
                    methods=["POST"],
                )
            )
            app.router.routes.append(
                Route(
                    "/authorize",
                    endpoint=self._permissive_authorize_endpoint,
                    methods=["GET"],
                )
            )
            if self._consent_page in _BOUNCING_MODES:
                app.router.routes.append(
                    Route(
                        "/authorize/consent",
                        endpoint=self._bounced_consent_endpoint,
                        methods=["GET"],
                    )
                )
        app.router.routes.extend(self._route_set.routes())
        app.router.routes.append(
            Route(
                "/.well-known/jwks.json",
                endpoint=self._jwks_endpoint,
                methods=["GET"],
            )
        )
        if self._test_mint_endpoint:
            app.router.routes.append(
                Route(
                    "/test-only/mint-token",
                    endpoint=self._test_mint_endpoint_handler,
                    methods=["POST"],
                )
            )

    def _should_install_permissive_register(self) -> bool:
        return self._allow_dcr and not self._dcr_strict

    def _should_replace_route(self, route: Route) -> bool:
        return self._should_install_permissive_register() and route.path in ("/register", "/authorize")

    async def _permissive_register_endpoint(self, request: Request) -> Response:
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "body must be JSON"},
                status_code=400,
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "body must be a JSON object"},
                status_code=400,
            )
        redirect_uris = body.get("redirect_uris", [])
        requested_auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
        is_public_client = requested_auth_method == "none"
        client_id = f"vuln-dcr-{secrets.token_hex(8)}"
        client_secret = None if is_public_client else f"vuln-secret-{secrets.token_hex(16)}"
        now = int(time.time())
        self._register_permissive_client(
            client_id, client_secret, redirect_uris, requested_auth_method
        )
        response_body: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": now,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": requested_auth_method,
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
        }
        if client_secret is not None:
            response_body["client_secret"] = client_secret
        if "client_name" in body:
            response_body["client_name"] = body["client_name"]
            # Retain the attacker-controlled client_name so the consent page can reflect it —
            # the precondition the consent-page reflected-XSS check probes for.
            self._client_names[client_id] = str(body["client_name"])
        return JSONResponse(response_body, status_code=201)

    def _register_permissive_client(
        self,
        client_id: str,
        client_secret: str | None,
        redirect_uris: list[Any],
        token_endpoint_auth_method: str = "client_secret_post",
    ) -> None:
        validated: list[AnyUrl] = []
        for uri in redirect_uris:
            if not isinstance(uri, str):
                continue
            try:
                validated.append(AnyUrl(uri))
            except ValueError:
                continue
        if not validated:
            validated = [AnyUrl("http://localhost:33418/callback")]
        self._provider.add_preregistered_client(
            OAuthClientInformationFull(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uris=validated,
                token_endpoint_auth_method=token_endpoint_auth_method,
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
            )
        )

    async def _permissive_authorize_endpoint(self, request: Request) -> Response:
        params = request.query_params
        redirect_uri = params.get("redirect_uri", "")
        client_id = params.get("client_id", "")
        if not redirect_uri:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri is required"},
                status_code=400,
            )
        if self._authorize_reject_unsafe and _is_unsafe_redirect(redirect_uri):
            # Hardened-but-permissive: storage echoed it, but the authorization endpoint
            # enforces — exactly the registration-echo-vs-authorize-enforcement failure mode under test.
            return JSONResponse(
                {"error": "invalid_redirect_uri",
                 "error_description": "redirect_uri is not permitted for this client"},
                status_code=400,
            )
        if not _is_url_parseable(redirect_uri):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri is not a valid URI"},
                status_code=400,
            )
        if self._consent_page in _BOUNCING_MODES:
            return self._bounce_to_signin(client_id, redirect_uri)
        if self._consent_page != "none":
            return self._render_consent_page(client_id, redirect_uri=redirect_uri)
        # Vulnerable: honor the (possibly hostile) redirect target. Delegate to the provider so
        # the issued code is real (exchangeable at /token), keeping the full OAuth flow valid.
        client = await self._provider.get_client(client_id) or OAuthClientInformationFull(
            client_id=client_id or "vuln-dcr-unknown",
            redirect_uris=[AnyUrl(redirect_uri)],
            token_endpoint_auth_method="none",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
        )
        authorize_params = AuthorizationParams(
            state=params.get("state"),
            scopes=params.get("scope", "").split() or None,
            code_challenge=params.get("code_challenge", ""),
            redirect_uri=AnyUrl(redirect_uri),
            redirect_uri_provided_explicitly=True,
            resource=params.get("resource"),
        )
        location = await self._provider.authorize(client, authorize_params)
        return Response(status_code=302, headers={"Location": location})

    def _render_consent_page(self, client_id: str, *, redirect_uri: str) -> Response:
        client_name = self._client_names.get(client_id, client_id)
        if self._should_escape_client_name(redirect_uri):
            return self._render_escaped_consent_page(client_name)
        return self._render_reflecting_consent_page(client_name)

    def _should_escape_client_name(self, redirect_uri: str) -> bool:
        if self._consent_page == "safe":
            return True
        if self._consent_page == "bounce-loopback":
            # Loopback-trust shape: client_name is reflected raw ONLY for trusted (loopback) clients.
            return not _is_loopback_redirect(redirect_uri)
        if self._consent_page == "inverse-trust":
            # Inverse trust gate: client_name is reflected raw ONLY for the https redirect; loopback is
            # treated as untrusted. Proves dual-redirect probing catches the opposite trust gate.
            return _is_loopback_redirect(redirect_uri)
        # vulnerable / body-https / attribute / bounce-altparam / comment-only always reflect.
        return False

    @staticmethod
    def _render_escaped_consent_page(client_name: str) -> Response:
        # Hardened: HTML-escape the attacker-controlled client_name before rendering.
        rendered = html.escape(client_name)
        body = (
            "<!doctype html><html><head><title>Authorize</title></head><body>"
            f"<h1>Authorize {rendered}</h1>"
            "<form method=\"post\"><button>Allow</button></form>"
            "</body></html>"
        )
        return HTMLResponse(body, status_code=200)

    def _render_reflecting_consent_page(self, client_name: str) -> Response:
        renderer = {
            "body-https": _reflecting_body_html,
            "attribute": _reflecting_attribute_html,
            "comment-only": _comment_only_html,
        }.get(self._consent_page, _reflecting_script_island_html)
        return HTMLResponse(renderer(client_name), status_code=200)

    def _bounce_to_signin(self, client_id: str, redirect_uri: str) -> Response:
        # Login-bounce shape: /authorize 302s CROSS-ORIGIN to a sign-in page, embedding the real
        # AS-origin consent URL in a query param. The redirect_uri rides along so the consent endpoint
        # can apply its trust gate (a real server would store it against the auth session). The
        # bounce-loopback shape uses a postSignUp param; bounce-altparam uses an alternate param
        # (goto) to prove param-agnostic discovery.
        consent_url = (
            f"{self._issuer}/authorize/consent?"
            + urlencode({"client_id": client_id, "redirect_uri": redirect_uri})
        )
        consent_param = "postSignUp" if self._consent_page == "bounce-loopback" else "goto"
        location = f"{SIGNIN_URL}?" + urlencode(
            {consent_param: consent_url, "redirectTo": f"{self._issuer}/authorize"}
        )
        return Response(status_code=302, headers={"Location": location})

    async def _bounced_consent_endpoint(self, request: Request) -> Response:
        client_id = request.query_params.get("client_id", "")
        redirect_uri = request.query_params.get("redirect_uri", "")
        return self._render_consent_page(client_id, redirect_uri=redirect_uri)

    @staticmethod
    def _extract_bearer_token(request: Request) -> str | None:
        header = request.headers.get("authorization")
        if header is None:
            return None
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value:
            return None
        return value.strip()

    async def _jwks_endpoint(self, _request: Request) -> Response:
        return JSONResponse(self._signer.jwks())

    async def _test_mint_endpoint_handler(self, request: Request) -> Response:
        body: dict[str, Any] = {}
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except (json.JSONDecodeError, ValueError):
            body = {}
        subject = body.get("subject") or "test"
        raw_scopes = body.get("scopes") or []
        scopes = [str(s) for s in raw_scopes] if isinstance(raw_scopes, list) else []
        expires_in_raw = body.get("expires_in", ACCESS_TOKEN_LIFETIME_SECONDS)
        try:
            expires_in = int(expires_in_raw)
        except (TypeError, ValueError):
            expires_in = ACCESS_TOKEN_LIFETIME_SECONDS
        token = self._signer.sign(
            subject=str(subject), scopes=scopes, expires_in=expires_in
        )
        return JSONResponse({"access_token": token})


def parse_preregister_specs(raw: list[str]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for entry in raw:
        client_id, sep, client_secret = entry.partition(":")
        if not sep or not client_id:
            raise ValueError(
                f"--oauth-preregister expects CLIENT_ID:CLIENT_SECRET, got {entry!r}"
            )
        specs.append({"client_id": client_id, "client_secret": client_secret})
    return specs


__all__ = [
    "ACCESS_TOKEN_LIFETIME_SECONDS",
    "CONSENT_PAGE_MODES",
    "REFRESH_TOKEN_LIFETIME_SECONDS",
    "InMemoryOAuthProvider",
    "JwtSigner",
    "OAuthStrategy",
    "VerifyOptions",
    "parse_preregister_specs",
]
