from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import freezegun
import httpx
import pytest
import uvicorn
from starlette.testclient import TestClient
from tests._helpers import _free_port

from mcp_test_server import cli
from mcp_test_server.app import build_app
from mcp_test_server.auth import BrokenBearerStrategy
from mcp_test_server.oauth import ACCESS_TOKEN_LIFETIME_SECONDS, OAuthStrategy
from mcp_test_server.oauth_discovery import (
    AS_WELL_KNOWN_PATH,
    PRM_WELL_KNOWN_PATH,
    DiscoveryMode,
)

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "integration-test", "version": "0.1"},
        },
    }


def _parse_event_stream_result(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            payload: dict[str, Any] = json.loads(line[len("data: "):])
            return payload
    raise AssertionError(f"No SSE data frame in body: {body!r}")


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(build_app(), base_url="http://127.0.0.1:8000") as c:
        yield c


def test_streamable_http_initialize_returns_session_id(client: TestClient) -> None:
    response = client.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())

    assert response.status_code == 200
    assert response.headers.get("mcp-session-id")
    result = _parse_event_stream_result(response.text)
    assert "error" not in result
    assert result["result"]["serverInfo"]["name"] == "mcp-scanner-test-server"
    assert result["result"]["serverInfo"]["version"] == "0.1.0-vuln-fixture"


def test_sse_endpoint_advertises_message_url(live_server: str) -> None:
    with (
        httpx.Client(base_url=live_server, timeout=3.0) as http,
        http.stream("GET", "/sse") as response,
    ):
        assert response.status_code == 200
        event_line, data_line = "", ""
        for idx, line in enumerate(response.iter_lines()):
            if idx == 0:
                event_line = line
            elif idx == 1:
                data_line = line
                break

    assert event_line == "event: endpoint"
    assert data_line.startswith("data: ")
    advertised_url = data_line[len("data: "):]
    assert "session_id=" in advertised_url
    assert "/messages" in advertised_url


def _shttp_call(client: TestClient, payload: dict[str, Any],
                session_id: str | None = None) -> httpx.Response:
    headers = dict(_MCP_HEADERS)
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    return client.post("/mcp", headers=headers, json=payload)


def test_resources_list_returns_sample_resources(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]

    _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    resources = _parse_event_stream_result(list_response.text)["result"]["resources"]
    uris = {resource["uri"] for resource in resources}
    assert {
        "docs://readme",
        "docs://changelog",
        "data://users/sample",
        "status://health",
    } <= uris


def test_prompts_list_returns_sample_prompts(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]

    _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    prompts = _parse_event_stream_result(list_response.text)["result"]["prompts"]
    names = {prompt["name"] for prompt in prompts}
    assert {"summarize", "code_review"} <= names


def test_resource_templates_list_returns_user_profile_template(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]

    _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    templates = _parse_event_stream_result(list_response.text)["result"]["resourceTemplates"]
    uri_templates = {template["uriTemplate"] for template in templates}
    assert {"user://profile/{id}", "file:///{path}"} <= uri_templates


def test_tools_list_returns_both_plugins(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]

    notified = _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )
    assert notified.status_code in (200, 202)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    tools = _parse_event_stream_result(list_response.text)["result"]["tools"]
    tool_names = {tool["name"] for tool in tools}
    assert {"query_user", "ping_host"} <= tool_names


def test_tools_list_surfaces_annotations(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(
        client,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        session_id=session_id,
    )

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    tools = {tool["name"]: tool for tool
             in _parse_event_stream_result(list_response.text)["result"]["tools"]}

    assert tools["query_user"]["annotations"]["readOnlyHint"] is True
    assert tools["ping_host"]["annotations"]["readOnlyHint"] is False
    assert tools["ping_host"]["annotations"]["openWorldHint"] is True
    assert "annotations" not in tools["fetch_url"] or tools["fetch_url"].get("annotations") is None


def test_leaky_descriptions_tool_exposes_secrets_in_tools_list(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    tools = _parse_event_stream_result(list_response.text)["result"]["tools"]
    leaky = next(t for t in tools if t["name"] == "leaky_describe")
    description = leaky["description"]
    assert "admin@internal-corp.example" in description
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" in description
    assert "AKIAQ7777PYTYINTERNAL" in description
    assert "ghp_5tQk9XnVbZmRfHsCwLpYJgAaBcDeFgHiJk23" in description
    assert "xoxb-58291047362-71839204657-Kp9mTzWq3RvXbN7sLyHc2dFg" in description
    assert (
        "sk-ant-api03-"
        "Rk9pVz7mQx2LtBnW4cHsKpYq8DgJ3fXvUe6Za1MrTbN5wPdGkLh7sQ2VxCmZn8FtRbYpWq4Jd3Lx9KvHc6MsAgUe2BtNzAA"
        in description
    )
    assert "AIzaSyDx12345678901234567890ABCDEFGHIJK" in description
    assert "sk_live_5tQk9XnVbZmRfHsCwLpYJgAa" in description


def test_leaky_resource_exposes_secrets_in_resources_list(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    resources = _parse_event_stream_result(list_response.text)["result"]["resources"]
    leaky = next(r for r in resources if r["name"] == "leaky_internal_db")
    assert "DefaultEndpointsProtocol=https;AccountName=" in leaky["description"]
    assert "\"type\":\"service_account\"" in leaky["description"]
    assert "\"private_key\":" in leaky["description"]
    assert "192.168.1.10" in leaky["uri"]


def test_leaky_prompt_exposes_secrets_in_prompts_list(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    prompts = _parse_event_stream_result(list_response.text)["result"]["prompts"]
    leaky = next(p for p in prompts if p["name"] == "leaky_payment_email")
    description = leaky["description"]
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in description
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in description
    assert "4111111111111111" in description


def test_poisoned_icons_tool_appears_in_tools_list_with_icons(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    tools = _parse_event_stream_result(list_response.text)["result"]["tools"]
    poisoned = next(t for t in tools if t["name"] == "poisoned_icons_demo")
    assert len(poisoned["icons"]) == 5
    assert poisoned["icons"][0]["src"] == "javascript:alert(1)"


def test_poisoned_icons_resource_appears_in_resources_list_with_icons(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    resources = _parse_event_stream_result(list_response.text)["result"]["resources"]
    poisoned = next(r for r in resources if r["name"] == "poisoned_icons_resource")
    assert len(poisoned["icons"]) == 5
    assert poisoned["icons"][0]["src"] == "javascript:alert(1)"


def test_poisoned_icons_prompt_appears_in_prompts_list_with_icons(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    session_id = init_response.headers["mcp-session-id"]
    _shttp_call(client, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                session_id=session_id)

    list_response = _shttp_call(
        client,
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}},
        session_id=session_id,
    )
    assert list_response.status_code == 200
    prompts = _parse_event_stream_result(list_response.text)["result"]["prompts"]
    poisoned = next(p for p in prompts if p["name"] == "poisoned_icons_prompt")
    assert len(poisoned["icons"]) == 5
    assert poisoned["icons"][0]["src"] == "javascript:alert(1)"


def test_server_info_icons_advertised_in_initialize(client: TestClient) -> None:
    init_response = _shttp_call(client, _initialize_payload())
    assert init_response.status_code == 200
    server_info = _parse_event_stream_result(init_response.text)["result"]["serverInfo"]
    assert server_info["icons"][0]["src"] == "javascript:alert('serverInfo')"
    assert server_info["icons"][1]["src"] == "http://example.test/server-icon.png"


def test_build_app_respects_enabled_filter() -> None:
    app = build_app(enabled={"query_user"})
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        init = _shttp_call(c, _initialize_payload())
        assert init.status_code == 200
        session_id = init.headers["mcp-session-id"]
        _shttp_call(c, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    session_id=session_id)
        listed = _shttp_call(c,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            session_id=session_id)

    tools = _parse_event_stream_result(listed.text)["result"]["tools"]
    tool_names = {tool["name"] for tool in tools}
    assert tool_names == {"query_user"}


def test_build_app_raises_when_no_plugins_registered() -> None:
    with pytest.raises(RuntimeError, match="No plugins registered"):
        build_app(enabled={"nonexistent"})


def test_cli_main_with_list_plugins_does_not_start_server(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch.object(cli, "uvicorn") as uvicorn_mock:
        cli.main(["--list-plugins"])

    uvicorn_mock.run.assert_not_called()
    stdout = capsys.readouterr().out
    assert "query_user" in stdout
    assert "ping_host" in stdout


def test_build_app_passes_host_to_fastmcp() -> None:
    app = build_app(host="0.0.0.0")
    with TestClient(app, base_url="http://example.com:8765") as c:
        response = c.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())

    assert response.status_code == 200
    assert response.headers.get("mcp-session-id")


def test_build_app_default_accepts_non_loopback_host_header() -> None:
    # Default ships vulnerable to DNS rebinding (CVE-2025-66416 fixture):
    # a non-loopback Host header must NOT be rejected.
    app = build_app()
    with TestClient(app, base_url="http://example.com:8765") as c:
        response = c.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())

    assert response.status_code == 200
    assert response.headers.get("mcp-session-id")


def test_default_accepts_hostile_origin() -> None:
    app = build_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        headers = {**_MCP_HEADERS, "Origin": "http://evil.example"}
        response = c.post("/mcp", headers=headers, json=_initialize_payload())

    assert response.status_code == 200
    result = _parse_event_stream_result(response.text)
    assert "error" not in result
    assert result["result"]["serverInfo"]["name"] == "mcp-scanner-test-server"


def test_transport_security_enabled_rejects_hostile_origin() -> None:
    app = build_app(transport_security="enabled")
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        headers = {**_MCP_HEADERS, "Origin": "http://evil.example"}
        response = c.post("/mcp", headers=headers, json=_initialize_payload())

    assert response.status_code == 403
    assert "Invalid Origin header" in response.text


def test_transport_security_enabled_rejects_bad_host() -> None:
    app = build_app(transport_security="enabled")
    with TestClient(app, base_url="http://attacker.example:8000") as c:
        response = c.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())

    assert response.status_code == 421
    assert "Invalid Host header" in response.text


def test_transport_security_enabled_allows_loopback_origin() -> None:
    app = build_app(transport_security="enabled")
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        headers = {**_MCP_HEADERS, "Origin": "http://127.0.0.1:8000"}
        response = c.post("/mcp", headers=headers, json=_initialize_payload())

    assert response.status_code == 200
    assert response.headers.get("mcp-session-id")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@dataclass
class OAuthHarness:
    base_url: str
    strategy: OAuthStrategy

    def register_client(self, redirect_uri: str) -> dict[str, Any]:
        with httpx.Client(base_url=self.base_url, timeout=3.0) as http:
            response = http.post("/register", json={"redirect_uris": [redirect_uri]})
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

    def authorize_and_get_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        state: str,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        with httpx.Client(base_url=self.base_url, timeout=3.0, follow_redirects=False) as http:
            response = http.get("/authorize", params=params)
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        query = parse_qs(urlsplit(location).query)
        assert query.get("state") == [state], f"state mismatch: {query}"
        return query["code"][0]

    def exchange_code(
        self,
        *,
        client_id: str,
        client_secret: str | None,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }
        if client_secret is not None:
            data["client_secret"] = client_secret
        with httpx.Client(base_url=self.base_url, timeout=3.0) as http:
            response = http.post("/token", data=data)
        assert response.status_code == 200, response.text
        return response.json()  # type: ignore[no-any-return]

    def exchange_refresh_token(
        self,
        *,
        client_id: str,
        client_secret: str | None,
        refresh_token: str,
    ) -> httpx.Response:
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }
        if client_secret is not None:
            data["client_secret"] = client_secret
        with httpx.Client(base_url=self.base_url, timeout=3.0) as http:
            return http.post("/token", data=data)


@contextmanager
def _oauth_harness(
    *,
    allow_dcr: bool = True,
    preregistered_clients: list[dict[str, Any]] | None = None,
    discovery_mode: DiscoveryMode = DiscoveryMode.FULL,
    skip_signature_check: bool = False,
    accept_alg_none: bool = False,
    skip_audience_check: bool = False,
    skip_issuer_check: bool = False,
    skip_expiry_check: bool = False,
    dcr_strict: bool = False,
) -> Iterator[OAuthHarness]:
    port = _free_port()
    issuer = f"http://127.0.0.1:{port}"
    audience = f"{issuer}/mcp"
    strategy = OAuthStrategy(
        issuer=issuer,
        audience=audience,
        allow_dcr=allow_dcr,
        preregistered_clients=preregistered_clients,
        discovery_mode=discovery_mode,
        skip_signature_check=skip_signature_check,
        accept_alg_none=accept_alg_none,
        skip_audience_check=skip_audience_check,
        skip_issuer_check=skip_issuer_check,
        skip_expiry_check=skip_expiry_check,
        dcr_strict=dcr_strict,
    )
    app = build_app(auth=strategy)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            server.run()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        if errors:
            raise RuntimeError("uvicorn failed to start") from errors[0]
        raise RuntimeError("uvicorn did not start within 5s")
    try:
        yield OAuthHarness(base_url=issuer, strategy=strategy)
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def _initialize_with_token(http: httpx.Client, access_token: str) -> str:
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {access_token}"}
    response = http.post("/mcp", headers=headers, json=_initialize_payload())
    assert response.status_code == 200, response.text
    return response.headers["mcp-session-id"]


def _post_mcp(
    http: httpx.Client,
    payload: dict[str, Any],
    *,
    access_token: str,
    session_id: str | None = None,
) -> httpx.Response:
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {access_token}"}
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    return http.post("/mcp", headers=headers, json=payload)


def _call_query_user(harness: OAuthHarness, access_token: str) -> httpx.Response:
    with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
        session_id = _initialize_with_token(http, access_token)
        notified = _post_mcp(
            http,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            access_token=access_token,
            session_id=session_id,
        )
        assert notified.status_code in (200, 202)
        return _post_mcp(
            http,
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "query_user", "arguments": {"username": "alice"}},
            },
            access_token=access_token,
            session_id=session_id,
        )


_REDIRECT_URI = "http://localhost:33418/callback"


def test_oauth_dcr_full_flow() -> None:
    with _oauth_harness(allow_dcr=True) as harness:
        client = harness.register_client(_REDIRECT_URI)
        verifier, challenge = _pkce_pair()
        code = harness.authorize_and_get_code(
            client_id=client["client_id"],
            redirect_uri=_REDIRECT_URI,
            code_challenge=challenge,
            state="dcr-state",
        )
        tokens = harness.exchange_code(
            client_id=client["client_id"],
            client_secret=client["client_secret"],
            code=code,
            code_verifier=verifier,
            redirect_uri=_REDIRECT_URI,
        )
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == ACCESS_TOKEN_LIFETIME_SECONDS

        response = _call_query_user(harness, tokens["access_token"])
        assert response.status_code == 200
        result = _parse_event_stream_result(response.text)
        assert "error" not in result, result


def test_oauth_manual_mode() -> None:
    preregistered = {"client_id": "manual-client", "client_secret": "manual-secret"}
    with _oauth_harness(allow_dcr=False, preregistered_clients=[preregistered]) as harness:
        with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
            register_response = http.post(
                "/register", json={"redirect_uris": [_REDIRECT_URI]}
            )
        assert register_response.status_code == 404

        verifier, challenge = _pkce_pair()
        code = harness.authorize_and_get_code(
            client_id="manual-client",
            redirect_uri=_REDIRECT_URI,
            code_challenge=challenge,
            state="manual-state",
        )
        tokens = harness.exchange_code(
            client_id="manual-client",
            client_secret="manual-secret",
            code=code,
            code_verifier=verifier,
            redirect_uri=_REDIRECT_URI,
        )

        response = _call_query_user(harness, tokens["access_token"])
        assert response.status_code == 200


def test_oauth_missing_token_401() -> None:
    with (
        _oauth_harness(allow_dcr=True) as harness,
        httpx.Client(base_url=harness.base_url, timeout=3.0) as http,
    ):
        response = http.post("/mcp", headers=_MCP_HEADERS, json=_initialize_payload())
    assert response.status_code == 401
    challenge = response.headers.get("www-authenticate", "")
    assert "Bearer" in challenge
    assert "resource_metadata=" in challenge


def test_oauth_expired_token_refresh() -> None:
    with _oauth_harness(allow_dcr=True) as harness:
        client = harness.register_client(_REDIRECT_URI)
        verifier, challenge = _pkce_pair()
        code = harness.authorize_and_get_code(
            client_id=client["client_id"],
            redirect_uri=_REDIRECT_URI,
            code_challenge=challenge,
            state="refresh-state",
        )
        tokens = harness.exchange_code(
            client_id=client["client_id"],
            client_secret=client["client_secret"],
            code=code,
            code_verifier=verifier,
            redirect_uri=_REDIRECT_URI,
        )

        future = dt.datetime.fromtimestamp(
            time.time() + ACCESS_TOKEN_LIFETIME_SECONDS + 5,
            tz=dt.UTC,
        )
        with freezegun.freeze_time(future, tick=True):
            with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
                expired_response = http.post(
                    "/mcp",
                    headers={
                        **_MCP_HEADERS,
                        "Authorization": f"Bearer {tokens['access_token']}",
                    },
                    json=_initialize_payload(),
                )
            assert expired_response.status_code == 401

            refresh_response = harness.exchange_refresh_token(
                client_id=client["client_id"],
                client_secret=client["client_secret"],
                refresh_token=tokens["refresh_token"],
            )
            assert refresh_response.status_code == 200, refresh_response.text
            refreshed = refresh_response.json()
            assert refreshed["access_token"] != tokens["access_token"]

            response = _call_query_user(harness, refreshed["access_token"])
        assert response.status_code == 200


def test_oauth_audience_rejected() -> None:
    with _oauth_harness(allow_dcr=True) as harness:
        wrong_aud_token = harness.strategy.signer.sign_claims(
            {
                "iss": harness.strategy.issuer,
                "sub": "test",
                "aud": "https://evil.example.com",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
            }
        )
        with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
            response = http.post(
                "/mcp",
                headers={**_MCP_HEADERS, "Authorization": f"Bearer {wrong_aud_token}"},
                json=_initialize_payload(),
            )
    assert response.status_code == 401


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_unsigned_jwt(claims: dict[str, Any]) -> str:
    header = json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    payload = json.dumps(claims, separators=(",", ":")).encode()
    return f"{_b64url_no_pad(header)}.{_b64url_no_pad(payload)}."


def _valid_claims(harness: OAuthHarness) -> dict[str, Any]:
    return {
        "iss": harness.strategy.issuer,
        "sub": "test",
        "aud": harness.strategy.audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
    }


def _post_initialize(base_url: str, token: str) -> httpx.Response:
    with httpx.Client(base_url=base_url, timeout=3.0) as http:
        return http.post(
            "/mcp",
            headers={**_MCP_HEADERS, "Authorization": f"Bearer {token}"},
            json=_initialize_payload(),
        )


def test_oauth_skip_signature_accepts_garbage_signature() -> None:
    with _oauth_harness(skip_signature_check=True) as harness:
        valid_token = harness.strategy.signer.sign_claims(_valid_claims(harness))
        header, payload, _ = valid_token.split(".")
        forged = f"{header}.{payload}.{_b64url_no_pad(b'not-a-real-signature')}"
        response = _post_initialize(harness.base_url, forged)
    assert response.status_code == 200


def test_oauth_default_rejects_garbage_signature() -> None:
    with _oauth_harness() as harness:
        valid_token = harness.strategy.signer.sign_claims(_valid_claims(harness))
        header, payload, _ = valid_token.split(".")
        forged = f"{header}.{payload}.{_b64url_no_pad(b'not-a-real-signature')}"
        response = _post_initialize(harness.base_url, forged)
    assert response.status_code == 401


def test_oauth_accept_alg_none_accepts_unsigned_token() -> None:
    with _oauth_harness(accept_alg_none=True) as harness:
        unsigned = _build_unsigned_jwt(_valid_claims(harness))
        unsigned_response = _post_initialize(harness.base_url, unsigned)
        signed_token = harness.strategy.signer.sign_claims(_valid_claims(harness))
        signed_response = _post_initialize(harness.base_url, signed_token)
    assert unsigned_response.status_code == 200
    assert signed_response.status_code == 200


def test_oauth_default_rejects_unsigned_token() -> None:
    with _oauth_harness() as harness:
        unsigned = _build_unsigned_jwt(_valid_claims(harness))
        response = _post_initialize(harness.base_url, unsigned)
    assert response.status_code == 401


def test_oauth_accept_alg_none_still_rejects_garbage_rs256_signature() -> None:
    with _oauth_harness(accept_alg_none=True) as harness:
        valid_token = harness.strategy.signer.sign_claims(_valid_claims(harness))
        header, payload, _ = valid_token.split(".")
        forged = f"{header}.{payload}.{_b64url_no_pad(b'not-a-real-signature')}"
        response = _post_initialize(harness.base_url, forged)
    assert response.status_code == 401


def test_oauth_accept_alg_none_rejects_non_object_payload() -> None:
    with _oauth_harness(accept_alg_none=True) as harness:
        header = json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
        payload = json.dumps([1, 2, 3], separators=(",", ":")).encode()
        non_object_token = f"{_b64url_no_pad(header)}.{_b64url_no_pad(payload)}."
        response = _post_initialize(harness.base_url, non_object_token)
    assert response.status_code == 401


def test_oauth_skip_audience_accepts_wrong_aud() -> None:
    with _oauth_harness(skip_audience_check=True) as harness:
        wrong_aud_token = harness.strategy.signer.sign_claims(
            {**_valid_claims(harness), "aud": "https://evil.example.com"}
        )
        response = _post_initialize(harness.base_url, wrong_aud_token)
    assert response.status_code == 200


def test_oauth_skip_issuer_accepts_wrong_iss() -> None:
    with _oauth_harness(skip_issuer_check=True) as harness:
        wrong_iss_token = harness.strategy.signer.sign_claims(
            {**_valid_claims(harness), "iss": "https://evil.example.com"}
        )
        response = _post_initialize(harness.base_url, wrong_iss_token)
    assert response.status_code == 200


def test_oauth_skip_expiry_accepts_expired_token() -> None:
    with _oauth_harness(skip_expiry_check=True) as harness:
        expired_token = harness.strategy.signer.sign_claims(
            {**_valid_claims(harness), "iat": 1, "exp": 1}
        )
        response = _post_initialize(harness.base_url, expired_token)
    assert response.status_code == 200


def test_oauth_skip_audience_and_issuer_compose() -> None:
    with _oauth_harness(skip_audience_check=True, skip_issuer_check=True) as harness:
        token = harness.strategy.signer.sign_claims(
            {
                **_valid_claims(harness),
                "aud": "https://evil.example.com",
                "iss": "https://evil.example.com",
            }
        )
        response = _post_initialize(harness.base_url, token)
    assert response.status_code == 200


_ALL_WELL_KNOWN: tuple[str, ...] = (PRM_WELL_KNOWN_PATH, AS_WELL_KNOWN_PATH)

_DISCOVERY_MODE_EXPECTATIONS: tuple[tuple[DiscoveryMode, frozenset[str], bool], ...] = (
    (DiscoveryMode.FULL,        frozenset({PRM_WELL_KNOWN_PATH, AS_WELL_KNOWN_PATH}), True),
    (DiscoveryMode.HEADER_ONLY, frozenset(),                                          True),
    (DiscoveryMode.PRM_ONLY,    frozenset({PRM_WELL_KNOWN_PATH}),                     False),
    (DiscoveryMode.AS_ONLY,     frozenset({AS_WELL_KNOWN_PATH}),                      False),
    (DiscoveryMode.NONE,        frozenset(),                                          False),
)


class TestOauthDiscoveryModes:
    @pytest.mark.parametrize(
        "mode, expected_paths, _includes_metadata",
        _DISCOVERY_MODE_EXPECTATIONS,
    )
    def test_well_known_paths(
        self,
        mode: DiscoveryMode,
        expected_paths: frozenset[str],
        _includes_metadata: bool,
    ) -> None:
        with _oauth_harness(discovery_mode=mode) as harness:
            with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
                for path in _ALL_WELL_KNOWN:
                    response = http.get(path)
                    if path in expected_paths:
                        assert response.status_code == 200, (mode, path, response.text)
                    else:
                        assert response.status_code == 404, (mode, path, response.text)

    @pytest.mark.parametrize(
        "mode, _expected_paths, includes_metadata",
        _DISCOVERY_MODE_EXPECTATIONS,
    )
    def test_www_authenticate_header(
        self,
        mode: DiscoveryMode,
        _expected_paths: frozenset[str],
        includes_metadata: bool,
    ) -> None:
        with _oauth_harness(discovery_mode=mode) as harness:
            with httpx.Client(base_url=harness.base_url, timeout=3.0) as http:
                response = http.post(
                    "/mcp",
                    headers=_MCP_HEADERS,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                )
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        if includes_metadata:
            assert "resource_metadata=" in challenge, (mode, challenge)
        else:
            assert "resource_metadata=" not in challenge, (mode, challenge)


class TestHiddenMethodsBypassAuth:
    @pytest.fixture
    def oauth_protected_client(self) -> Iterator[TestClient]:
        strategy = OAuthStrategy(
            issuer="http://127.0.0.1:8000",
            audience="http://127.0.0.1:8000/mcp",
            allow_dcr=True,
        )
        with TestClient(build_app(auth=strategy), base_url="http://127.0.0.1:8000") as c:
            yield c

    def test_legitimate_mcp_call_without_token_returns_401(
        self, oauth_protected_client: TestClient,
    ) -> None:
        response = oauth_protected_client.post(
            "/mcp", headers=_MCP_HEADERS, json=_initialize_payload(),
        )
        assert response.status_code == 401

    def test_debug_info_returns_payload_without_authorization_header(
        self, oauth_protected_client: TestClient,
    ) -> None:
        response = oauth_protected_client.post(
            "/mcp",
            headers=_MCP_HEADERS,
            json={"jsonrpc": "2.0", "id": 1, "method": "debug/info", "params": {}},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["result"] == {
            "server": "mcp-scanner-test-server",
            "build": "vuln-fixture",
            "uptime_seconds": 12345,
        }


class TestBrokenBearerStrategy:
    @pytest.fixture
    def broken_bearer_client(self) -> Iterator[TestClient]:
        with TestClient(build_app(auth=BrokenBearerStrategy()),
                        base_url="http://127.0.0.1:8000") as c:
            yield c

    @pytest.mark.parametrize(
        "auth_header",
        [
            "Bearer valid-looking-token",
            "Bearer not_a_real_token_12345",
            None,
        ],
    )
    def test_initialize_succeeds_regardless_of_bearer(
        self, broken_bearer_client: TestClient, auth_header: str | None,
    ) -> None:
        headers = dict(_MCP_HEADERS)
        if auth_header is not None:
            headers["Authorization"] = auth_header

        response = broken_bearer_client.post(
            "/mcp", headers=headers, json=_initialize_payload(),
        )

        assert response.status_code == 200, response.text
        assert "www-authenticate" not in {k.lower() for k in response.headers.keys()}
