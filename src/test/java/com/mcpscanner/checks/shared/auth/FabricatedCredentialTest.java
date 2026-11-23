package com.mcpscanner.checks.shared.auth;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class FabricatedCredentialTest {

    @Test
    void bearerStrategyGetsAnInvalidCanaryBearerToken() {
        FabricatedCredential credential = FabricatedCredential.of(new BearerTokenAuthStrategy("t"), "c4n4ry");

        assertThat(credential.headers()).containsExactly(Map.entry("Authorization", "Bearer invalid_c4n4ry"));
    }

    @Test
    void customHeaderStrategyGetsTheInvalidCanaryInItsOwnHeader() {
        FabricatedCredential credential = FabricatedCredential.of(
                new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "k")), "c4n4ry");

        assertThat(credential.headers()).containsExactly(Map.entry("X-Api-Key", "invalid_c4n4ry"));
    }

    @Test
    void cookieIsNotTreatedAsTheCredentialHeader() {
        FabricatedCredential credential = FabricatedCredential.of(
                new CustomHeaderAuthStrategy(Map.of("Cookie", "a=b")), "c4n4ry");

        assertThat(credential.headers()).containsExactly(Map.entry("Authorization", "Bearer invalid_c4n4ry"));
    }
}
