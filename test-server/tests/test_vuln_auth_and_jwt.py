from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_test_server.oauth.signer import KEY_ID
from tests.conftest import ServerFactory
from tests.support import BASE_URL, McpSession, TestServer, tool_text

ALL_JWT = ("jwt_forged_signature", "jwt_alg_none", "jwt_hs256_key_confusion", "jwt_empty_key_unknown_kid",
           "jwt_wrong_audience", "jwt_wrong_issuer", "jwt_expired")
EVERY_METHOD = (
    ("tools/call", {"name": "echo", "arguments": {"message": "x"}}),
    ("resources/read", {"uri": "docs://readme"}),
    ("prompts/get", {"name": "summarize", "arguments": {"text": "x"}}),
    ("tools/list", {}),
    ("resources/list", {}),
    ("resources/templates/list", {}),
    ("prompts/list", {}),
    ("completion/complete", {"ref": {"type": "ref/prompt", "name": "code_review"},
                             "argument": {"name": "language", "value": ""}}),
    ("logging/setLevel", {"level": "info"}),
    ("ping", {}),
    ("resources/subscribe", {"uri": "docs://readme"}),
    ("server/discover", {}),
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    return {"iss": BASE_URL, "aud": f"{BASE_URL}/mcp", "sub": "attacker", "iat": now, "exp": now + 600, **overrides}


def _forged_rs256(**overrides: Any) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return jwt.encode(_claims(**overrides), key, algorithm="RS256")


def _alg_none() -> str:
    return f"{_b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{_b64(json.dumps(_claims()).encode())}."


def _hs256_with(key: bytes, kid: str | None = None) -> str:
    header_fields = {"alg": "HS256", "typ": "JWT"} | ({"kid": kid} if kid is not None else {})
    header = _b64(json.dumps(header_fields).encode())
    signing_input = f"{header}.{_b64(json.dumps(_claims()).encode())}"
    signature = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def _strict(make_server: ServerFactory, **vulns: str) -> TestServer:
    return make_server(default_mode="safe", vulns=vulns)


def _bearer_session(server: TestServer, token: str) -> McpSession:
    return server.session({"authorization": f"Bearer {token}"}, initialize=False)


def _accepted(server: TestServer, token: str) -> bool:
    return _bearer_session(server, token).initialize().status_code == 200


@pytest.mark.parametrize(("method", "params"), EVERY_METHOD)
def test_anonymous_execution_on_every_method(make_server: ServerFactory, method: str, params: dict[str, Any]) -> None:
    vulnerable = make_server(default_mode="safe", vulns={"unauthenticated_execution": "vulnerable"})
    assert "result" in vulnerable.session().request(method, params)
    safe = _strict(make_server)
    session = safe.session(initialize=False)
    assert session.post(session.message(method, params)).status_code == 401


def test_anonymous_notifications(make_server: ServerFactory) -> None:
    vulnerable = make_server(default_mode="safe", vulns={"unauthenticated_execution": "vulnerable"})
    assert vulnerable.session().notify("notifications/initialized").status_code == 202
    safe = _strict(make_server)
    assert safe.session(initialize=False).notify("notifications/initialized").status_code == 401


def test_safe_challenge_points_at_resource_metadata(make_server: ServerFactory) -> None:
    response = _strict(make_server).session(initialize=False).initialize()
    assert 'resource_metadata="http://testserver/.well-known/oauth-protected-resource/mcp"' in (
        response.headers["www-authenticate"]
    )


def test_valid_token_and_malformed_credentials(make_server: ServerFactory) -> None:
    server = make_server(
        vulns={"unauthenticated_execution": "vulnerable", "auth_presence_only_credential": "safe",
               "auth_unknown_token_service_account": "safe"}
    )
    session = _bearer_session(server, server.token())
    session.initialize()
    assert tool_text(session.call_tool("echo", {"message": "ok"})) == "ok"
    for authorization in ("Bearer invalid.jwt.token", "Bearer ", "Basic abc", "Bearer not_a_real_token"):
        assert server.session({"authorization": authorization}, initialize=False).initialize().status_code == 401


@pytest.mark.parametrize(
    ("vuln", "token_factory"),
    [
        ("jwt_forged_signature", lambda server: _forged_rs256()),
        ("jwt_alg_none", lambda server: _alg_none()),
        ("jwt_hs256_key_confusion", lambda server: _hs256_with(server.client.get("/public-key.pem").content)),
        ("jwt_empty_key_unknown_kid", lambda server: _hs256_with(b"", kid="attacker-chosen-kid")),
        ("jwt_wrong_audience", lambda server: server.token(claims={"aud": "urn:scancheck:untrusted-audience"})),
        ("jwt_wrong_issuer", lambda server: server.token(claims={"iss": "urn:scancheck:untrusted-issuer"})),
        ("jwt_expired", lambda server: server.token(claims={"exp": int(time.time()) - 60})),
    ],
)
def test_jwt_weakness_fires_only_in_vulnerable_mode(make_server: ServerFactory, vuln: str, token_factory: Any) -> None:
    vulnerable = _strict(make_server, **{vuln: "vulnerable"})
    assert _accepted(vulnerable, token_factory(vulnerable))
    safe = _strict(make_server)
    assert not _accepted(safe, token_factory(safe))


def test_hs256_with_wrong_key_rejected_even_when_vulnerable(make_server: ServerFactory) -> None:
    server = _strict(make_server, jwt_hs256_key_confusion="vulnerable")
    assert not _accepted(server, _hs256_with(b"wrong-fixture-key"))


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: _hs256_with(b"", kid=KEY_ID),
        lambda: _hs256_with(b""),
        lambda: _hs256_with(b"wrong-fixture-key", kid="attacker-chosen-kid"),
    ],
)
def test_empty_key_unknown_kid_needs_both_an_unknown_kid_and_the_empty_key(
        make_server: ServerFactory, token_factory: Any) -> None:
    server = _strict(make_server, jwt_empty_key_unknown_kid="vulnerable")
    assert not _accepted(server, token_factory())


def test_weaknesses_do_not_compose_implicitly(make_server: ServerFactory) -> None:
    server = _strict(make_server, jwt_wrong_issuer="vulnerable")
    assert not _accepted(server, _forged_rs256(iss="urn:scancheck:untrusted-issuer"))
    both = _strict(make_server, jwt_wrong_issuer="vulnerable", jwt_forged_signature="vulnerable")
    assert _accepted(both, _forged_rs256(iss="urn:scancheck:untrusted-issuer"))


def test_runtime_mode_switch(make_server: ServerFactory) -> None:
    server = _strict(make_server)
    token = _alg_none()
    assert not _accepted(server, token)
    server.set_modes(jwt_alg_none="vulnerable")
    assert _accepted(server, token)
    server.set_modes(jwt_alg_none="safe")
    assert not _accepted(server, token)


def test_jwks_matches_signing_key(server: TestServer) -> None:
    jwks = server.client.get("/jwks.json").json()
    key = jwt.PyJWK(jwks["keys"][0]).key
    claims = jwt.decode(server.token(), key, algorithms=["RS256"], audience=f"{BASE_URL}/mcp")
    assert claims["iss"] == BASE_URL
