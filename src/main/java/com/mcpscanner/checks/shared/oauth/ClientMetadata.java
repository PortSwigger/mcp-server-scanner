package com.mcpscanner.checks.shared.oauth;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.List;
import java.util.Optional;

public record ClientMetadata(String clientName, List<String> redirectUris, List<String> grantTypes,
                             Optional<String> softwareId) {

    private static final String CODE_GRANT = "authorization_code";
    private static final String REFRESH_GRANT = "refresh_token";

    public ClientMetadata {
        redirectUris = List.copyOf(redirectUris);
        grantTypes = List.copyOf(grantTypes);
    }

    public ClientMetadata(String clientName, List<String> redirectUris, List<String> grantTypes) {
        this(clientName, redirectUris, grantTypes, Optional.empty());
    }

    public static ClientMetadata codeGrant(String clientName, List<String> redirectUris) {
        return new ClientMetadata(clientName, redirectUris, List.of(CODE_GRANT));
    }

    public ClientMetadata withRefreshGrant() {
        return new ClientMetadata(clientName, redirectUris, List.of(CODE_GRANT, REFRESH_GRANT), softwareId);
    }

    public ClientMetadata withSoftwareId(String id) {
        return new ClientMetadata(clientName, redirectUris, grantTypes, Optional.of(id));
    }

    String toJson() {
        ObjectNode body = McpObjectMapper.INSTANCE.createObjectNode().put("client_name", clientName);
        redirectUris.forEach(body.putArray("redirect_uris")::add);
        grantTypes.forEach(body.putArray("grant_types")::add);
        body.putArray("response_types").add("code");
        body.put("token_endpoint_auth_method", "none");
        softwareId.ifPresent(id -> body.put("software_id", id));
        return body.toString();
    }
}
