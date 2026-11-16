from __future__ import annotations

from mcp_test_server.vulns import registry

EXPECTED = {
    "unauthenticated_execution", "auth_forwarded_loopback_trust", "auth_session_credential",
    "auth_presence_only_credential", "auth_sibling_route",
    "jwt_forged_signature", "jwt_alg_none", "jwt_hs256_key_confusion", "jwt_empty_key_unknown_kid",
    "jwt_wrong_audience", "jwt_wrong_issuer", "jwt_expired",
    "origin_admission", "host_admission",
    "traversal_plain", "traversal_encoded", "traversal_prefix_sibling",
    "shell_command_injection", "blind_shell_command_injection", "python_eval_injection",
    "javascript_eval_injection", "sql_table_injection", "sql_literal_injection",
    "fetch_tool_arguments", "fetch_resource_uri", "fetch_list_cursor", "fetch_meta", "fetch_client_info",
    "fetch_headers", "fetch_oauth_client_metadata",
    "downstream_route_escape", "downstream_raw_segment", "downstream_encoded_dot_segment",
    "redirect_unregistered", "redirect_http_downgrade", "redirect_path_normalisation",
    "redirect_script_scheme_registration", "redirect_wildcard_registration",
    "consent_client_name_reflection", "consent_state_reflection",
    "refresh_missing_client_secret", "refresh_wrong_client_secret", "refresh_scope_expansion",
    "cross_identity_object", "cross_identity_resource", "cross_identity_role", "cross_identity_session",
    "code_reuse", "code_redemption_race",
    "session_guessable_ids", "session_delete_ignored",
}
DROPPED_PASSIVE_FIXTURES = ("leaky", "poisoned", "hidden_method")


def test_registry_discovers_exactly_the_v1_vulnerabilities() -> None:
    assert registry.vulnerability_names() == EXPECTED


def test_every_vulnerability_documents_itself() -> None:
    for vulnerability in registry.vulnerability_types():
        assert vulnerability.summary.strip()


def test_passive_only_fixtures_are_gone(server) -> None:  # type: ignore[no-untyped-def]
    session = server.session()
    names: list[str] = []
    for method, key in (("tools/list", "tools"), ("prompts/list", "prompts"), ("resources/list", "resources")):
        params: dict[str, str] = {}
        while True:
            result = session.result(method, params)
            names += [entry.get("name", "") for entry in result[key]]
            if "nextCursor" not in result:
                break
            params = {"cursor": result["nextCursor"]}
    assert not [name for name in names if any(marker in name for marker in DROPPED_PASSIVE_FIXTURES)]
    assert "icons" not in str(session.result("server/discover"))
