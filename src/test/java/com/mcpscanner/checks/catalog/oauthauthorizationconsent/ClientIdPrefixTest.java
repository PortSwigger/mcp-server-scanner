package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIdPrefixTest {

    @ParameterizedTest
    @CsvSource({
            "burp-mcp_a1b2c3d4e5f6, burp-mcp",
            "acme.agent:Xy7Pq2Lm9, acme.agent",
            "tenant-7_3f2a9c1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b, tenant-7",
            "8d0f3c5e-2a71-4b9e-a6d4-5f1c9e7b3a20_Ab12Cd34Ef56Gh78, 8d0f3c5e-2a71-4b9e-a6d4-5f1c9e7b3a20"})
    void theStructuredPrefixIsTheTextBeforeARandomLookingTail(String clientId, String prefix) {
        assertThat(ClientIdPrefix.of(clientId)).map(ClientIdPrefix::value).contains(prefix);
    }

    @ParameterizedTest
    @ValueSource(strings = {"3f2a9c1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", "scanner-client", "abcdef1234567890",
            "_a1b2c3d4e5f6", "app-a1b2-c3d4"})
    void aBareUuidOrAShortTailHasNoStructuredPrefix(String clientId) {
        assertThat(ClientIdPrefix.of(clientId)).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"burp-mcp_z9y8x7w6v5, true", "burp-mcp-ext_z9y8x7w6v5, false", "other_z9y8x7w6v5, false"})
    void anotherClientIdSharesThePrefixOnlyWhenItsOwnPrefixIsTheSame(String clientId, boolean shared) {
        assertThat(ClientIdPrefix.of("burp-mcp_a1b2c3d4e5f6").orElseThrow().sharedBy(clientId)).isEqualTo(shared);
    }
}
