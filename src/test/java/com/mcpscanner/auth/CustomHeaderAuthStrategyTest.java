package com.mcpscanner.auth;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomHeaderAuthStrategyTest {

    @Test
    void headersReturnsAllEntries() {
        Map<String, String> input = Map.of("X-Api-Key", "abc123", "X-Tenant", "acme");
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(input);

        assertThat(strategy.headers()).containsExactlyInAnyOrderEntriesOf(input);
    }

    @Test
    void headersReturnsEmptyMapWhenNoHeaders() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(Map.of());

        assertThat(strategy.headers()).isEmpty();
    }

    @Test
    void headersReturnsDefensiveCopy() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "abc123"));

        assertThatThrownBy(() -> strategy.headers().put("X-New", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void constructorTakesDefensiveCopyOfInput() {
        HashMap<String, String> mutableInput = new HashMap<>();
        mutableInput.put("X-Api-Key", "abc123");

        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(mutableInput);
        mutableInput.put("X-Injected", "evil");

        assertThat(strategy.headers()).doesNotContainKey("X-Injected");
        assertThat(strategy.headers()).containsOnlyKeys("X-Api-Key");
    }

    @Test
    void contributedHeaderNamesReturnsAllHeaderKeys() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(
                Map.of("X-Api-Key", "abc", "X-Tenant", "acme"));

        assertThat(strategy.contributedHeaderNames())
                .containsExactlyInAnyOrder("X-Api-Key", "X-Tenant");
    }

    @Test
    void contributedHeaderNamesMatchesCaseInsensitively() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(
                Map.of("X-Api-Key", "abc"));

        assertThat(strategy.contributedHeaderNames()).contains("x-api-key");
    }

    @Test
    void refreshIsNoOpAndReportsNothingHappened() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(
                Map.of("X-Api-Key", "abc"));

        assertThat(strategy.refresh()).isFalse();
    }

    @Test
    void doesNotSupportRefresh() {
        CustomHeaderAuthStrategy strategy = new CustomHeaderAuthStrategy(
                Map.of("X-Api-Key", "abc"));

        assertThat(strategy.supportsRefresh()).isFalse();
    }
}
