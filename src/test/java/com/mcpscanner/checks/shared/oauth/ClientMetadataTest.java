package com.mcpscanner.checks.shared.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClientMetadataTest {

    private static final ClientMetadata CODE_GRANT = ClientMetadata.codeGrant("probe", List.of("http://127.0.0.1/cb"));

    @Test
    void aCodeGrantClientIsAPublicClientForTheCodeGrantOnly() throws Exception {
        JsonNode json = McpObjectMapper.INSTANCE.readTree(CODE_GRANT.toJson());

        assertThat(json.path("grant_types").toString()).isEqualTo("[\"authorization_code\"]");
        assertThat(json.path("token_endpoint_auth_method").asText()).isEqualTo("none");
        assertThat(json.path("redirect_uris").toString()).isEqualTo("[\"http://127.0.0.1/cb\"]");
    }

    @Test
    void addingTheRefreshGrantKeepsEverythingElse() {
        ClientMetadata withRefresh = CODE_GRANT.withRefreshGrant();

        assertThat(withRefresh.grantTypes()).containsExactly("authorization_code", "refresh_token");
        assertThat(withRefresh.clientName()).isEqualTo("probe");
        assertThat(withRefresh.redirectUris()).isEqualTo(CODE_GRANT.redirectUris());
    }

    @Test
    void carriesASoftwareIdOnlyWhenGiven() throws Exception {
        ClientMetadata withSoftware = CODE_GRANT.withSoftwareId("acme-agent").withRefreshGrant();

        assertThat(McpObjectMapper.INSTANCE.readTree(withSoftware.toJson()).path("software_id").asText())
                .isEqualTo("acme-agent");
        assertThat(McpObjectMapper.INSTANCE.readTree(CODE_GRANT.toJson()).has("software_id")).isFalse();
    }
}
