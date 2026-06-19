from urllib.parse import parse_qs, unquote, urlparse

from starlette.testclient import TestClient

from mcp_test_server.app import build_app
from mcp_test_server.oauth import OAuthStrategy

_CANARY = "mcpxss-abc</script><mcpxss-canary-abc></mcpxss-canary-abc>"
_CANARY_TAG = "<mcpxss-canary-abc>"
_CANARY_ENCODED = "&lt;mcpxss-canary-abc&gt;"
_ISSUER = "http://127.0.0.1:8000"
_LOOPBACK_REDIRECT = "http://127.0.0.1:53682/callback"
_HTTPS_REDIRECT = "https://probe.example/cb"


def _client(*, consent_page: str) -> TestClient:
    strategy = OAuthStrategy(
        issuer=_ISSUER,
        audience=f"{_ISSUER}/mcp",
        allow_dcr=True,
        dcr_strict=False,
        consent_page=consent_page,
    )
    return TestClient(build_app(auth=strategy), base_url=_ISSUER)


def _register_and_authorize(http: TestClient, *, redirect_uri: str = "https://probe.example/cb"):
    registered = http.post(
        "/register",
        json={"client_name": _CANARY, "redirect_uris": [redirect_uri]},
    )
    client_id = registered.json()["client_id"]
    consent = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "state-123",
        },
        follow_redirects=False,
    )
    return registered, consent


def test_vulnerable_consent_page_reflects_client_name_unescaped_in_script_island():
    with _client(consent_page="vulnerable") as http:
        _, consent = _register_and_authorize(http)

    assert consent.status_code == 200, consent.text
    assert "text/html" in consent.headers["content-type"]
    # The raw breakout tag survives un-encoded inside a <script> island, no CSP.
    assert _CANARY_TAG in consent.text
    assert "<script" in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


def test_safe_consent_page_html_escapes_client_name():
    with _client(consent_page="safe") as http:
        _, consent = _register_and_authorize(http)

    assert consent.status_code == 200, consent.text
    assert "text/html" in consent.headers["content-type"]
    # The raw breakout tag must NOT survive; only the entity-encoded form is present.
    assert _CANARY_TAG not in consent.text
    assert "&lt;mcpxss-canary-abc&gt;" in consent.text


def test_consent_page_none_keeps_legacy_302_redirect_behavior():
    with _client(consent_page="none") as http:
        _, consent = _register_and_authorize(http)

    assert consent.status_code == 302, consent.text
    assert consent.headers["location"].startswith("https://probe.example/cb")


# --- bounce-loopback variant: trust-gated reflection behind a cross-origin login bounce ---


def _consent_url_from_login_bounce(location: str) -> str:
    """Pull the embedded consent URL out of the cross-origin sign-in Location's postSignUp param."""
    query = parse_qs(urlparse(location).query)
    return unquote(query["postSignUp"][0])


def test_bounce_loopback_variant_loopback_redirect_bounces_to_cross_origin_signin_carrying_consent_url():
    with _client(consent_page="bounce-loopback") as http:
        _, authorize = _register_and_authorize(http, redirect_uri=_LOOPBACK_REDIRECT)

    # /authorize bounces CROSS-ORIGIN to a sign-in page (the cross-origin login-bounce shape).
    assert authorize.status_code == 302, authorize.text
    location = authorize.headers["location"]
    assert urlparse(location).hostname not in (None, "127.0.0.1"), location
    assert "postSignUp=" in location
    # The embedded consent URL is AS-origin (issuer host), so the AS-origin-only check will fetch it.
    consent_url = _consent_url_from_login_bounce(location)
    assert urlparse(consent_url).hostname == "127.0.0.1", consent_url
    assert "/authorize/consent" in consent_url


def test_bounce_loopback_variant_consent_endpoint_reflects_client_name_unescaped_in_script_island_for_loopback():
    with _client(consent_page="bounce-loopback") as http:
        _, authorize = _register_and_authorize(http, redirect_uri=_LOOPBACK_REDIRECT)
        consent_path = urlparse(_consent_url_from_login_bounce(authorize.headers["location"]))
        consent = http.get(f"{consent_path.path}?{consent_path.query}", follow_redirects=False)

    assert consent.status_code == 200, consent.text
    assert "text/html" in consent.headers["content-type"]
    # Trusted (loopback) client → raw breakout survives inside a <script> island, no CSP.
    assert _CANARY_TAG in consent.text
    assert "<script" in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


def test_bounce_loopback_variant_non_loopback_redirect_is_not_trusted_and_escapes_client_name():
    with _client(consent_page="bounce-loopback") as http:
        _, authorize = _register_and_authorize(http, redirect_uri="https://probe.example/cb")
        consent_path = urlparse(_consent_url_from_login_bounce(authorize.headers["location"]))
        consent = http.get(f"{consent_path.path}?{consent_path.query}", follow_redirects=False)

    assert consent.status_code == 200, consent.text
    # Untrusted (non-loopback) client → client_name HTML-escaped, raw breakout must NOT survive.
    assert _CANARY_TAG not in consent.text
    assert "&lt;mcpxss-canary-abc&gt;" in consent.text


# --- body-https variant: direct 200 consent, raw reflection in a plain HTML body element ---


def test_body_https_variant_reflects_client_name_raw_in_plain_body_for_https_redirect():
    with _client(consent_page="body-https") as http:
        _, consent = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)

    # No login bounce: GET /authorize answers 200 with the consent HTML directly.
    assert consent.status_code == 200, consent.text
    assert "text/html" in consent.headers["content-type"]
    # Raw breakout survives in a plain HTML body element (an <h1>), NOT inside a <script> island.
    assert _CANARY_TAG in consent.text
    body_before_marker = consent.text[: consent.text.index(_CANARY_TAG)]
    assert "<h1" in body_before_marker
    assert "<script" not in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


# --- bounce-altparam variant: login bounce carrying the consent URL in a NON-postSignUp param ---


def test_bounce_altparam_variant_carries_consent_url_in_goto_param_not_post_sign_up():
    with _client(consent_page="bounce-altparam") as http:
        _, authorize = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)

    assert authorize.status_code == 302, authorize.text
    location = authorize.headers["location"]
    # The consent URL is carried in an alternate param name (no postSignUp).
    assert "postSignUp=" not in location
    assert "goto=" in location
    query = parse_qs(urlparse(location).query)
    consent_url = unquote(query["goto"][0])
    # Embedded consent URL is AS-origin, so the param-agnostic resolver will find and fetch it.
    assert urlparse(consent_url).hostname == "127.0.0.1", consent_url
    assert "/authorize/consent" in consent_url


def test_bounce_altparam_variant_consent_reflects_client_name_raw():
    with _client(consent_page="bounce-altparam") as http:
        _, authorize = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)
        query = parse_qs(urlparse(authorize.headers["location"]).query)
        consent_path = urlparse(unquote(query["goto"][0]))
        consent = http.get(f"{consent_path.path}?{consent_path.query}", follow_redirects=False)

    assert consent.status_code == 200, consent.text
    assert _CANARY_TAG in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


# --- attribute variant: raw breakout into an HTML attribute value ---


def test_attribute_variant_reflects_client_name_raw_in_an_attribute_value():
    with _client(consent_page="attribute") as http:
        _, consent = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)

    assert consent.status_code == 200, consent.text
    assert _CANARY_TAG in consent.text
    # The reflection lands inside an href attribute value, un-encoded, outside any <script> island.
    assert 'href="' in consent.text
    assert "<script" not in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


# --- inverse-trust variant: reflects ONLY for the https redirect (inverse of the loopback gate) ---


def test_inverse_trust_variant_reflects_client_name_raw_for_https_redirect():
    with _client(consent_page="inverse-trust") as http:
        _, consent = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)

    assert consent.status_code == 200, consent.text
    # HTTPS redirect is the trusted style here → raw breakout survives.
    assert _CANARY_TAG in consent.text
    assert "content-security-policy" not in {k.lower() for k in consent.headers}


def test_inverse_trust_variant_escapes_client_name_for_loopback_redirect():
    with _client(consent_page="inverse-trust") as http:
        _, consent = _register_and_authorize(http, redirect_uri=_LOOPBACK_REDIRECT)

    assert consent.status_code == 200, consent.text
    # Loopback is UNtrusted here (the inverse of the loopback gate) → escaped, no raw breakout.
    assert _CANARY_TAG not in consent.text
    assert _CANARY_ENCODED in consent.text


# --- comment-only variant: marker survives only inside an HTML comment (non-executable) ---


def test_comment_only_variant_reflects_marker_only_inside_an_html_comment():
    with _client(consent_page="comment-only") as http:
        _, consent = _register_and_authorize(http, redirect_uri=_HTTPS_REDIRECT)

    assert consent.status_code == 200, consent.text
    assert _CANARY_TAG in consent.text
    # The marker survives ONLY inside an HTML comment that is not closed before it.
    marker_index = consent.text.index(_CANARY_TAG)
    comment_open = consent.text.rfind("<!--", 0, marker_index)
    assert comment_open >= 0
    comment_close = consent.text.find("-->", comment_open)
    assert comment_close == -1 or comment_close > marker_index
