package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScannerSentinelsTest {

    @Test
    void routesToProxyNamesTheSentinelsThatSendARequestThroughTheLocalProxy() {
        assertThat(ScannerSentinels.ROUTES_TO_PROXY).containsExactlyInAnyOrder(
                ScannerSentinels.AUDIT_CAPABILITY_HEADER, ScannerSentinels.STRIP_AUTH_HEADER,
                ScannerSentinels.IDENTITY_HEADER);
    }

    @Test
    void strippedBeforeUpstreamNamesEverySentinelTheProxyRemovesBeforeForwarding() {
        assertThat(ScannerSentinels.STRIPPED_BEFORE_UPSTREAM).containsExactlyInAnyOrder(
                ScannerSentinels.AUDIT_CAPABILITY_HEADER, ScannerSentinels.STRIP_AUTH_HEADER,
                ScannerSentinels.IDENTITY_HEADER, ScannerSentinels.KEEP_SESSION_HEADER,
                ScannerSentinels.ROUTED_HEADER);
    }

    @Test
    void everySentinelHeaderIsInAllIncludingTheResponseOnlyExchangeHeader() {
        assertThat(ScannerSentinels.ALL).contains(
                ScannerSentinels.STRIP_AUTH_HEADER, ScannerSentinels.AUDIT_CAPABILITY_HEADER,
                ScannerSentinels.KEEP_SESSION_HEADER, ScannerSentinels.DIRECT_DELIVERY_HEADER,
                ScannerSentinels.IDENTITY_HEADER, ScannerSentinels.GENERATED_REGISTRATION_HEADER,
                ScannerSentinels.EXCHANGE_HEADER, ScannerSentinels.ROUTED_HEADER);
    }

    @Test
    void routedHeaderDoesNotItselfSendARequestThroughTheProxy() {
        assertThat(ScannerSentinels.ROUTES_TO_PROXY).doesNotContain(ScannerSentinels.ROUTED_HEADER);
        assertThat(ScannerSentinels.ALL).contains(ScannerSentinels.ROUTED_HEADER);
    }

    @Test
    void everyProxyRoutingSentinelIsStrippedBeforeUpstream() {
        assertThat(ScannerSentinels.STRIPPED_BEFORE_UPSTREAM).containsAll(ScannerSentinels.ROUTES_TO_PROXY);
    }

    @Test
    void sentinelSetsMatchHeaderNamesCaseInsensitively() {
        assertThat(ScannerSentinels.ROUTES_TO_PROXY.contains("x-mcp-scanner-identity")).isTrue();
        assertThat(ScannerSentinels.STRIPPED_BEFORE_UPSTREAM.contains("X-MCP-SCANNER-KEEP-SESSION")).isTrue();
    }

    @Test
    void sentinelSetsAreUnmodifiable() {
        assertThatThrownBy(() -> ScannerSentinels.ROUTES_TO_PROXY.add("X-Other"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> ScannerSentinels.STRIPPED_BEFORE_UPSTREAM.add("X-Other"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
