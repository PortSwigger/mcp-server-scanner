from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from mcp_test_server.cli import build_parser, cli_layer
from mcp_test_server.oauth.server_context import DEFAULT_SCOPE, ConsentMode
from mcp_test_server.oauth.sign_in import FIXTURE_PASSWORD, FIXTURE_USERNAME, SESSION_COOKIE
from mcp_test_server.settings import ServerSettings, settings_from_environment
from tests.conftest import ServerFactory
from tests.support import TestServer, pkce_pair

SCANNER_NAME = "MCP Server Scanner"
SCANNER_SOFTWARE_ID = "mcp-server-scanner"
SCANNER_REDIRECT = "http://127.0.0.1:47390/callback"
BROADER_SCOPE = f"{DEFAULT_SCOPE} mcp:admin"


def _sign_in(server: TestServer, password: str = FIXTURE_PASSWORD) -> httpx.Response:
    return server.client.post("/login", data={"username": FIXTURE_USERNAME, "password": password})


def _register(server: TestServer, name: str, redirect_uri: str, **metadata: Any) -> str:
    response = server.client.post("/register", json={"client_name": name, "redirect_uris": [redirect_uri],
                                                     "token_endpoint_auth_method": "none", **metadata})
    assert response.status_code == 201, response.text
    return str(response.json()["client_id"])


def _authorize(server: TestServer, client_id: str, redirect_uri: str, scope: str = DEFAULT_SCOPE,
               **extra: str) -> httpx.Response:
    _, challenge = pkce_pair()
    return server.client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "state": "st",
        "code_challenge": challenge, "code_challenge_method": "S256", "scope": scope, **extra})


def _code_without_interaction(response: httpx.Response, redirect_uri: str) -> bool:
    location = response.headers.get("location", "")
    return response.status_code == 302 and location.startswith(redirect_uri) and "code=" in location


def _is_consent_page(response: httpx.Response) -> bool:
    return response.status_code == 200 and 'action="/authorize/consent"' in response.text


def _approve(server: TestServer, page: httpx.Response) -> httpx.Response:
    fields = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page.text))
    return server.client.post("/authorize/consent", data={**fields, "decision": "approve"})


def _signed_in_with_scanner(make_server: ServerFactory, mode: str, **overrides: Any) -> tuple[TestServer, str]:
    server = make_server(consent=mode, **overrides)
    assert _sign_in(server).status_code == 200
    scanner = _register(server, SCANNER_NAME, SCANNER_REDIRECT, software_id=SCANNER_SOFTWARE_ID)
    page = _authorize(server, scanner, SCANNER_REDIRECT)
    if _is_consent_page(page):
        assert _code_without_interaction(_approve(server, page), SCANNER_REDIRECT)
    return server, scanner


def _fresh_name(server: TestServer) -> httpx.Response:
    redirect = "http://localhost:47391/fresh"
    return _authorize(server, _register(server, "Fresh probe 1f3a", redirect), redirect)


def _same_name(server: TestServer) -> httpx.Response:
    redirect = "http://localhost:47391/same-name"
    return _authorize(server, _register(server, SCANNER_NAME, redirect), redirect)


def _same_redirect_host(server: TestServer) -> httpx.Response:
    redirect = "http://127.0.0.1:47392/other-path"
    return _authorize(server, _register(server, "Fresh probe 2b7c", redirect), redirect)


def _same_client_id_prefix(server: TestServer) -> httpx.Response:
    redirect = "http://localhost:47391/prefix"
    client = _register(server, "Fresh probe 3d9e", redirect, software_id=SCANNER_SOFTWARE_ID)
    return _authorize(server, client, redirect)


def _scope_upgrade(server: TestServer, scanner: str) -> httpx.Response:
    assert _code_without_interaction(_authorize(server, scanner, SCANNER_REDIRECT), SCANNER_REDIRECT)
    return _authorize(server, scanner, SCANNER_REDIRECT, scope=BROADER_SCOPE)


PROBES = ("fresh_name", "same_name", "same_redirect_host", "same_client_id_prefix", "scope_upgrade")
SKIPPED_PROBES = {
    "signed-in-auto": set(PROBES),
    "remember-by-name": {"same_name"},
    "remember-by-redirect-host": {"same_redirect_host"},
    "remember-by-client-id-prefix": {"same_client_id_prefix"},
    "remember-ignores-scope": {"scope_upgrade"},
    "remember-by-client": set(),
}


def _probe(name: str, server: TestServer, scanner: str) -> httpx.Response:
    if name == "scope_upgrade":
        return _scope_upgrade(server, scanner)
    probes = {"fresh_name": _fresh_name, "same_name": _same_name, "same_redirect_host": _same_redirect_host,
              "same_client_id_prefix": _same_client_id_prefix}
    return probes[name](server)


@pytest.mark.parametrize("mode", SKIPPED_PROBES)
@pytest.mark.parametrize("probe", PROBES)
def test_each_consent_mode_skips_consent_only_for_its_keying_bug(make_server: ServerFactory, mode: str,
                                                                 probe: str) -> None:
    server, scanner = _signed_in_with_scanner(make_server, mode)
    response = _probe(probe, server, scanner)
    if probe in SKIPPED_PROBES[mode]:
        assert response.status_code == 302 and "code=" in response.headers["location"], response.text
    else:
        assert _is_consent_page(response), response.text


@pytest.mark.parametrize("mode", SKIPPED_PROBES)
def test_authorize_without_a_session_shows_the_login_page(make_server: ServerFactory, mode: str) -> None:
    server = make_server(consent=mode)
    client = _register(server, SCANNER_NAME, SCANNER_REDIRECT)
    response = _authorize(server, client, SCANNER_REDIRECT)
    assert response.status_code == 200
    assert 'action="/login"' in response.text
    assert "code=" not in response.headers.get("location", "")
    refused = _authorize(server, client, SCANNER_REDIRECT, prompt="none")
    assert "error=login_required" in refused.headers["location"]


def test_login_sets_an_http_only_session_cookie_and_refuses_wrong_credentials(make_server: ServerFactory) -> None:
    server = make_server(consent="remember-by-client")
    assert _sign_in(server, password="wrong").status_code == 401
    signed_in = _sign_in(server)
    cookie = signed_in.headers["set-cookie"]
    assert cookie.startswith(SESSION_COOKIE + "=")
    assert "httponly" in cookie.lower()


def test_login_returns_to_a_local_next_path_only(make_server: ServerFactory) -> None:
    server = make_server(consent="remember-by-client")
    credentials = {"username": FIXTURE_USERNAME, "password": FIXTURE_PASSWORD}
    local = server.client.post("/login", data={**credentials, "next": "/authorize?client_id=x"})
    assert local.status_code == 303 and local.headers["location"] == "/authorize?client_id=x"
    elsewhere = server.client.post("/login", data={**credentials, "next": "//evil.example/"})
    assert elsewhere.status_code == 200


def test_consent_decision_needs_a_signed_in_user(make_server: ServerFactory) -> None:
    server = make_server(consent="remember-by-client")
    _sign_in(server)
    client = _register(server, SCANNER_NAME, SCANNER_REDIRECT)
    page = _authorize(server, client, SCANNER_REDIRECT)
    server.client.cookies.clear()
    assert _approve(server, page).status_code == 401


def test_remembered_consent_belongs_to_the_signed_in_user_and_its_approved_scopes(
        make_server: ServerFactory) -> None:
    server, scanner = _signed_in_with_scanner(make_server, "remember-by-client")
    assert _code_without_interaction(_authorize(server, scanner, SCANNER_REDIRECT), SCANNER_REDIRECT)
    broader = _authorize(server, scanner, SCANNER_REDIRECT, scope=BROADER_SCOPE)
    assert _is_consent_page(broader)
    assert _code_without_interaction(_approve(server, broader), SCANNER_REDIRECT)
    assert _code_without_interaction(_authorize(server, scanner, SCANNER_REDIRECT, scope=BROADER_SCOPE),
                                     SCANNER_REDIRECT)


def test_signed_in_user_is_the_subject_of_the_issued_token(make_server: ServerFactory) -> None:
    server, scanner = _signed_in_with_scanner(make_server, "remember-by-client", default_mode="safe")
    assert server.session(initialize=False).initialize().status_code == 401
    verifier, challenge = pkce_pair()
    response = server.client.get("/authorize", params={
        "response_type": "code", "client_id": scanner, "redirect_uri": SCANNER_REDIRECT, "state": "st",
        "code_challenge": challenge, "code_challenge_method": "S256", "scope": DEFAULT_SCOPE})
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    issued = server.client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                                "redirect_uri": SCANNER_REDIRECT, "code_verifier": verifier,
                                                "client_id": scanner})
    assert issued.status_code == 200, issued.text
    session = server.session({"authorization": "Bearer " + issued.json()["access_token"]}, initialize=False)
    assert session.initialize().status_code == 200


@pytest.mark.parametrize("mode", SKIPPED_PROBES)
def test_signed_in_modes_prefix_client_ids_with_the_software_id(make_server: ServerFactory, mode: str) -> None:
    server = make_server(consent=mode)
    prefixed = _register(server, SCANNER_NAME, SCANNER_REDIRECT, software_id=SCANNER_SOFTWARE_ID)
    assert re.fullmatch(SCANNER_SOFTWARE_ID + r"_[A-Za-z0-9]{16}", prefixed)
    unprefixed = _register(server, "Fresh", SCANNER_REDIRECT)
    assert re.fullmatch(r"[0-9a-f]{32}", unprefixed)


@pytest.mark.parametrize("mode", ["prompt", "auto"])
def test_anonymous_modes_keep_their_client_ids_and_need_no_sign_in(make_server: ServerFactory, mode: str) -> None:
    server = make_server(consent=mode)
    client = _register(server, SCANNER_NAME, SCANNER_REDIRECT, software_id=SCANNER_SOFTWARE_ID)
    assert client.startswith("dcr-")
    response = _authorize(server, client, SCANNER_REDIRECT)
    assert _code_without_interaction(response, SCANNER_REDIRECT) if mode == "auto" else _is_consent_page(response)


def test_scopes_supported_goes_beyond_the_default_scope(server: TestServer) -> None:
    metadata = server.client.get("/.well-known/oauth-authorization-server").json()
    assert DEFAULT_SCOPE in metadata["scopes_supported"]
    assert set(metadata["scopes_supported"]) - {DEFAULT_SCOPE}


@pytest.mark.parametrize("mode", SKIPPED_PROBES)
def test_consent_mode_is_set_by_environment_and_cli(mode: str) -> None:
    from_environment = ServerSettings.from_mapping(settings_from_environment({"MCP_TEST_CONSENT": mode}))
    from_cli = ServerSettings.from_mapping(cli_layer(build_parser().parse_args(["--consent", mode])))
    assert from_environment.consent is from_cli.consent is ConsentMode(mode)
