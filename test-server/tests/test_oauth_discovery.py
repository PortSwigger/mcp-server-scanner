import pytest
from starlette.testclient import TestClient

from mcp_test_server.app import build_app
from mcp_test_server.oauth import OAuthStrategy
from mcp_test_server.oauth_discovery import DiscoveryMode, DiscoveryRouteSet


_DIRTY_REDIRECT_URI = "javascript:alert(1)"


def _build_oauth_client(*, dcr_strict: bool) -> TestClient:
    strategy = OAuthStrategy(
        issuer="http://127.0.0.1:8000",
        audience="http://127.0.0.1:8000/mcp",
        allow_dcr=True,
        dcr_strict=dcr_strict,
    )
    return TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000")


class _FakeProvider:
    pass


_FAKE_PROVIDER = _FakeProvider()


@pytest.mark.parametrize(
    "mode, include_metadata",
    [
        (DiscoveryMode.FULL, True),
        (DiscoveryMode.HEADER_ONLY, True),
        (DiscoveryMode.PRM_ONLY, False),
        (DiscoveryMode.AS_ONLY, False),
        (DiscoveryMode.NONE, False),
    ],
)
def test_include_resource_metadata_in_challenge(mode, include_metadata):
    route_set = DiscoveryRouteSet(mode=mode, provider=None, issuer_url="http://x", audience="http://x/mcp")
    assert route_set.include_resource_metadata_in_challenge() is include_metadata


def _route_paths(mode):
    rs = DiscoveryRouteSet(mode=mode, provider=_FAKE_PROVIDER, issuer_url="http://x", audience="http://x/mcp")
    return {r.path for r in rs.routes()}


@pytest.mark.parametrize(
    "mode, expected_paths",
    [
        (DiscoveryMode.FULL,        {"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"}),
        (DiscoveryMode.HEADER_ONLY, set()),
        (DiscoveryMode.PRM_ONLY,    {"/.well-known/oauth-protected-resource"}),
        (DiscoveryMode.AS_ONLY,     {"/.well-known/oauth-authorization-server"}),
        (DiscoveryMode.NONE,        set()),
    ],
)
def test_routes_filtered_by_mode(mode, expected_paths):
    assert _route_paths(mode) == expected_paths


def test_default_register_accepts_unauth_post_with_dirty_redirect_uri():
    with _build_oauth_client(dcr_strict=False) as http:
        response = http.post(
            "/register",
            json={"client_name": "scanner-probe", "redirect_uris": [_DIRTY_REDIRECT_URI]},
        )

    assert response.status_code == 201, response.text
    body = response.json()
    assert "client_id" in body
    assert body["redirect_uris"] == [_DIRTY_REDIRECT_URI]


def test_strict_register_requires_bearer():
    with _build_oauth_client(dcr_strict=True) as http:
        response = http.post(
            "/register",
            json={"client_name": "scanner-probe",
                  "redirect_uris": ["http://localhost:33418/callback"]},
        )

    assert response.status_code in (401, 403), response.text


def test_strict_register_rejects_dirty_redirect_uri():
    with _build_oauth_client(dcr_strict=True) as http:
        response = http.post(
            "/register",
            json={"client_name": "scanner-probe",
                  "redirect_uris": [_DIRTY_REDIRECT_URI]},
        )

    assert response.status_code >= 400 and response.status_code < 500, response.text


def _build_oauth_client_authorize(*, reject_unsafe: bool) -> TestClient:
    strategy = OAuthStrategy(
        issuer="http://127.0.0.1:8000",
        audience="http://127.0.0.1:8000/mcp",
        allow_dcr=True,
        dcr_strict=False,
        authorize_reject_unsafe=reject_unsafe,
    )
    return TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000")


def _authorize(http: TestClient, redirect_uri: str):
    return http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "vuln-dcr-abc",
            "redirect_uri": redirect_uri,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "state-123",
        },
        follow_redirects=False,
    )


_UNSAFE_REDIRECT_URI = "http://attacker.example/cb"


def test_default_authorize_honors_unsafe_redirect():
    with _build_oauth_client_authorize(reject_unsafe=False) as http:
        response = _authorize(http, _UNSAFE_REDIRECT_URI)

    assert response.status_code == 302, response.text
    assert response.headers["location"].startswith(_UNSAFE_REDIRECT_URI)


def test_hardened_authorize_rejects_unsafe_redirect_even_though_register_echoes_it():
    with _build_oauth_client_authorize(reject_unsafe=True) as http:
        echoed = http.post(
            "/register",
            json={"client_name": "scanner-probe", "redirect_uris": [_DIRTY_REDIRECT_URI]},
        )
        rejected = _authorize(http, _UNSAFE_REDIRECT_URI)

    assert echoed.status_code == 201, echoed.text
    assert echoed.json()["redirect_uris"] == [_DIRTY_REDIRECT_URI]
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["error"] == "invalid_redirect_uri"


def test_hardened_authorize_still_honors_safe_redirect():
    with _build_oauth_client_authorize(reject_unsafe=True) as http:
        response = _authorize(http, "https://app.example/cb")

    assert response.status_code == 302, response.text
    assert response.headers["location"].startswith("https://app.example/cb")


def test_permissive_register_public_client_omits_client_secret():
    strategy = OAuthStrategy(
        issuer="http://127.0.0.1:8000",
        audience="http://127.0.0.1:8000/mcp",
        allow_dcr=True,
        dcr_strict=False,
    )
    with TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000") as http:
        response = http.post(
            "/register",
            json={
                "client_name": "public-pkce-probe",
                "redirect_uris": ["http://localhost:33418/callback"],
                "token_endpoint_auth_method": "none",
            },
        )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in body

    registered = strategy.provider._clients[body["client_id"]]
    assert registered.client_secret is None
    assert registered.token_endpoint_auth_method == "none"


def test_permissive_register_defaults_to_confidential_client():
    strategy = OAuthStrategy(
        issuer="http://127.0.0.1:8000",
        audience="http://127.0.0.1:8000/mcp",
        allow_dcr=True,
        dcr_strict=False,
    )
    with TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000") as http:
        response = http.post(
            "/register",
            json={
                "client_name": "confidential-probe",
                "redirect_uris": ["http://localhost:33418/callback"],
            },
        )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token_endpoint_auth_method"] == "client_secret_post"
    assert body["client_secret"]

    registered = strategy.provider._clients[body["client_id"]]
    assert registered.client_secret == body["client_secret"]
    assert registered.token_endpoint_auth_method == "client_secret_post"


def test_permissive_register_explicit_client_secret_post_keeps_secret():
    strategy = OAuthStrategy(
        issuer="http://127.0.0.1:8000",
        audience="http://127.0.0.1:8000/mcp",
        allow_dcr=True,
        dcr_strict=False,
    )
    with TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000") as http:
        response = http.post(
            "/register",
            json={
                "client_name": "confidential-probe",
                "redirect_uris": ["http://localhost:33418/callback"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token_endpoint_auth_method"] == "client_secret_post"
    assert body["client_secret"]

    registered = strategy.provider._clients[body["client_id"]]
    assert registered.client_secret == body["client_secret"]
    assert registered.token_endpoint_auth_method == "client_secret_post"
