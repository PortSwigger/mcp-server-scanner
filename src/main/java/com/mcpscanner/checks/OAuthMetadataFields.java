package com.mcpscanner.checks;

import java.util.List;

public final class OAuthMetadataFields {

    public static final List<String> PRM_SCALAR_URL_FIELDS = List.of(
            "resource",
            "jwks_uri",
            "resource_documentation",
            "resource_policy_uri",
            "resource_tos_uri"
    );

    public static final List<String> PRM_ARRAY_URL_FIELDS = List.of(
            "authorization_servers"
    );

    public static final List<String> AS_SCALAR_URL_FIELDS = List.of(
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "registration_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
            "userinfo_endpoint",
            "device_authorization_endpoint",
            "end_session_endpoint",
            "service_documentation",
            "op_policy_uri",
            "op_tos_uri"
    );

    private OAuthMetadataFields() {}
}
