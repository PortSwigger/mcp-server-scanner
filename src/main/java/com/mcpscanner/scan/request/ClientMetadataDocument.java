package com.mcpscanner.scan.request;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.mcp.McpObjectMapper;

final class ClientMetadataDocument {

    private static final String CLIENT_HOME = "https://mcp-scanner.example.com";

    private ClientMetadataDocument() {}

    static ObjectNode full() {
        ObjectNode metadata = McpObjectMapper.INSTANCE.createObjectNode();
        metadata.putArray("redirect_uris").add("http://127.0.0.1:33418/callback");
        metadata.put("token_endpoint_auth_method", "none");
        metadata.putArray("grant_types").add("authorization_code").add("refresh_token");
        metadata.putArray("response_types").add("code");
        metadata.put("client_name", ExtensionMetadata.SCANNER_CLIENT_NAME);
        metadata.put("client_uri", CLIENT_HOME);
        metadata.put("logo_uri", CLIENT_HOME + "/logo.png");
        metadata.put("scope", "openid profile offline_access");
        metadata.putArray("contacts").add("security@mcp-scanner.example.com");
        metadata.put("tos_uri", CLIENT_HOME + "/terms");
        metadata.put("policy_uri", CLIENT_HOME + "/privacy");
        metadata.put("software_id", ExtensionMetadata.SOFTWARE_ID);
        metadata.put("software_version", ExtensionMetadata.VERSION);
        metadata.put("initiate_login_uri", CLIENT_HOME + "/login");
        return metadata;
    }
}
