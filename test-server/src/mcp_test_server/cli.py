from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass

import uvicorn

from mcp_test_server import registry
from mcp_test_server.app import build_app
from mcp_test_server.auth import AuthStrategy, BrokenBearerStrategy
from mcp_test_server.oauth import CONSENT_PAGE_MODES, OAuthStrategy, parse_preregister_specs
from mcp_test_server.oauth_discovery import DiscoveryMode


@dataclass(frozen=True)
class CliOptions:
    host: str
    port: int
    enable: tuple[str, ...] = ()
    disable: tuple[str, ...] = ()
    list_plugins: bool = False
    auth: str = "none"
    oauth_issuer: str | None = None
    oauth_issuer_override: str | None = None
    oauth_audience: str | None = None
    oauth_disable_dcr: bool = False
    oauth_preregister: tuple[str, ...] = ()
    oauth_discovery: str = DiscoveryMode.FULL.value
    oauth_skip_signature: bool = False
    oauth_accept_alg_none: bool = False
    oauth_skip_audience: bool = False
    oauth_skip_issuer: bool = False
    oauth_skip_expiry: bool = False
    oauth_dcr_strict: bool = False
    oauth_authorize_reject_unsafe: bool = False
    oauth_test_mint_endpoint: bool = False
    oauth_consent_page: str = "none"
    transport_security: str = "disabled"
    hidden_methods: str = "enabled"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-test-server",
                                description="Run the intentionally vulnerable MCP test server.")
    p.add_argument("--host", default="0.0.0.0", help="Interface to bind.")
    p.add_argument("--port", type=int, default=8000, help="Port to listen on.")
    p.add_argument("--enable", action="append", default=[], metavar="VULN",
                   help="Enable a vulnerability module (repeatable).")
    p.add_argument("--disable", action="append", default=[], metavar="VULN",
                   help="Disable a vulnerability module (repeatable).")
    p.add_argument("--list-plugins", action="store_true", help="List registered plugins and exit.")
    p.add_argument("--auth", choices=["none", "oauth", "broken-bearer"], default="none",
                   help="Authentication strategy.")
    p.add_argument("--oauth-issuer", metavar="URL", default=None,
                   help="OAuth issuer URL (default: http://<host>:<port>).")
    p.add_argument("--oauth-issuer-override", metavar="URL", default=None,
                   help="Override issuer/endpoint URLs in AS metadata (SSRF test fixture). "
                        "JWT signing still uses the real internal issuer.")
    p.add_argument("--oauth-audience", metavar="URL", default=None,
                   help="OAuth audience / resource URL (default: <issuer>/mcp).")
    p.add_argument("--oauth-disable-dcr", action="store_true",
                   help="Disable RFC 7591 dynamic client registration.")
    p.add_argument("--oauth-preregister", action="append", default=[],
                   metavar="CLIENT_ID:CLIENT_SECRET",
                   help="Preregister a static OAuth client (repeatable).")
    p.add_argument("--oauth-discovery",
                   choices=[mode.value for mode in DiscoveryMode],
                   default=DiscoveryMode.FULL.value,
                   help="OAuth discovery surface to expose (default: full).")
    p.add_argument("--oauth-skip-signature", action="store_true",
                   help="Vulnerable mode: accept JWTs without verifying signature.")
    p.add_argument("--oauth-accept-alg-none", action="store_true",
                   help="Vulnerable mode: accept JWTs with alg:none header.")
    p.add_argument("--oauth-skip-audience", action="store_true",
                   help="Vulnerable mode: skip audience claim validation.")
    p.add_argument("--oauth-skip-issuer", action="store_true",
                   help="Vulnerable mode: skip issuer claim validation.")
    p.add_argument("--oauth-skip-expiry", action="store_true",
                   help="Vulnerable mode: skip expiry claim validation.")
    p.add_argument("--oauth-dcr-strict", action="store_true",
                   help="Enforce RFC 7591: require Bearer for /register and validate "
                        "redirect_uris. Default off (vulnerable for differential testing).")
    p.add_argument("--oauth-authorize-reject-unsafe", action="store_true",
                   help="Hardened-but-permissive mode: /register still ECHOES hostile "
                        "redirect_uris (legal RFC 7591 storage), but GET /authorize REJECTS "
                        "them (400 invalid_redirect_uri). Models servers that enforce at "
                        "/authorize rather than at registration.")
    p.add_argument("--oauth-test-mint-endpoint", action="store_true",
                   help="TEST FIXTURE ONLY - expose POST /test-only/mint-token that returns "
                        "a signer-issued RS256 JWT with no authentication. Never enable in "
                        "production.")
    p.add_argument("--oauth-consent-page", choices=list(CONSENT_PAGE_MODES),
                   default="none",
                   help="Consent-page rendering at GET /authorize, exercising the reflected-XSS "
                        "check against a bug CLASS in many shapes. 'none' (default) keeps the legacy "
                        "302. 'safe' HTML-escapes client_name (no bug). 'vulnerable' reflects raw in "
                        "a <script> island, direct 200. 'bounce-loopback' is the full loopback-trust "
                        "shape: cross-origin login bounce (postSignUp) + raw reflection ONLY for "
                        "loopback redirect_uris. "
                        "'body-https' reflects raw in a plain HTML body element, direct 200. "
                        "'attribute' reflects raw inside an href attribute value. 'bounce-altparam' "
                        "is a login bounce carrying the consent URL in an alternate param (goto). "
                        "'inverse-trust' reflects raw ONLY for the https redirect (inverse of the "
                        "loopback gate). 'comment-only' reflects raw but only inside an HTML comment "
                        "(non-executable — must NOT fire).")
    p.add_argument("--transport-security", choices=["disabled", "enabled"], default="disabled",
                   help="DNS rebinding protection: 'disabled' (default, vulnerable) or 'enabled'.")
    p.add_argument("--hidden-methods", choices=["enabled", "disabled"], default="enabled",
                   help="Hidden method middleware: 'enabled' (default, vulnerable) or 'disabled' "
                        "(server returns -32601 for non-standard methods).")
    return p


def parse_args(argv: Sequence[str] | None = None) -> CliOptions:
    ns = build_parser().parse_args(argv)
    return CliOptions(
        host=ns.host,
        port=ns.port,
        enable=tuple(ns.enable),
        disable=tuple(ns.disable),
        list_plugins=ns.list_plugins,
        auth=ns.auth,
        oauth_issuer=ns.oauth_issuer,
        oauth_issuer_override=ns.oauth_issuer_override,
        oauth_audience=ns.oauth_audience,
        oauth_disable_dcr=ns.oauth_disable_dcr,
        oauth_preregister=tuple(ns.oauth_preregister),
        oauth_discovery=ns.oauth_discovery,
        oauth_skip_signature=ns.oauth_skip_signature,
        oauth_accept_alg_none=ns.oauth_accept_alg_none,
        oauth_skip_audience=ns.oauth_skip_audience,
        oauth_skip_issuer=ns.oauth_skip_issuer,
        oauth_skip_expiry=ns.oauth_skip_expiry,
        oauth_dcr_strict=ns.oauth_dcr_strict,
        oauth_authorize_reject_unsafe=ns.oauth_authorize_reject_unsafe,
        oauth_test_mint_endpoint=ns.oauth_test_mint_endpoint,
        oauth_consent_page=ns.oauth_consent_page,
        transport_security=ns.transport_security,
        hidden_methods=ns.hidden_methods,
    )


def _build_auth_strategy(opts: CliOptions) -> AuthStrategy | None:
    if opts.auth == "broken-bearer":
        return BrokenBearerStrategy()
    if opts.auth != "oauth":
        return None
    issuer = opts.oauth_issuer or f"http://{opts.host}:{opts.port}"
    audience = opts.oauth_audience or f"{issuer.rstrip('/')}/mcp"
    return OAuthStrategy(
        issuer=issuer,
        audience=audience,
        allow_dcr=not opts.oauth_disable_dcr,
        preregistered_clients=parse_preregister_specs(list(opts.oauth_preregister)),
        discovery_mode=DiscoveryMode(opts.oauth_discovery),
        skip_signature_check=opts.oauth_skip_signature,
        accept_alg_none=opts.oauth_accept_alg_none,
        skip_audience_check=opts.oauth_skip_audience,
        skip_issuer_check=opts.oauth_skip_issuer,
        skip_expiry_check=opts.oauth_skip_expiry,
        dcr_strict=opts.oauth_dcr_strict,
        authorize_reject_unsafe=opts.oauth_authorize_reject_unsafe,
        issuer_override=opts.oauth_issuer_override,
        test_mint_endpoint=opts.oauth_test_mint_endpoint,
        consent_page=opts.oauth_consent_page,
    )


def main(argv: Sequence[str] | None = None) -> None:
    opts = parse_args(argv)
    enabled = frozenset(opts.enable) if opts.enable else None
    disabled = frozenset(opts.disable) if opts.disable else None
    if opts.list_plugins:
        for plugin in registry.filter_plugins(enabled=enabled, disabled=disabled):
            print(f"{plugin.name}: {plugin.description}")
        return
    auth = _build_auth_strategy(opts)
    uvicorn.run(
        build_app(
            enabled=enabled,
            disabled=disabled,
            auth=auth,
            host=opts.host,
            transport_security=opts.transport_security,
            hidden_methods=opts.hidden_methods,
        ),
        host=opts.host,
        port=opts.port,
        log_level="info",
    )
