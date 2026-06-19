package com.mcpscanner.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NoAuthStrategyTest {

    private final NoAuthStrategy strategy = new NoAuthStrategy();

    @Test
    void headersReturnsEmptyMap() {
        assertThat(strategy.headers()).isEmpty();
    }

    @Test
    void contributedHeaderNamesIsEmpty() {
        assertThat(strategy.contributedHeaderNames()).isEmpty();
    }

    @Test
    void refreshIsNoOpAndReportsNothingHappened() {
        assertThat(strategy.refresh()).isFalse();
    }

    @Test
    void doesNotSupportRefresh() {
        assertThat(strategy.supportsRefresh()).isFalse();
    }
}
