package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class FramedOperationTest {

    @Test
    void recordsTheOperationHeadersTheScannerFramed() {
        String recorded = FramedOperation.encode(Map.of("Mcp-Method", "tools/call", "Mcp-Name", "slow",
                "MCP-Protocol-Version", "2026-07-28", "Mcp-Param-Tenant", "acme"));

        assertThat(FramedOperation.decode(recorded)).contains(new FramedOperation(Map.of(
                "mcp-method", "tools/call", "mcp-name", "slow", "mcp-protocol-version", "2026-07-28")));
    }

    @Test
    void aHeaderValueIsTheFramedOneOnlyWhenItMatchesExactly() {
        FramedOperation framed = FramedOperation.decode(FramedOperation.encode(Map.of("mcp-name", "slow"))).orElseThrow();

        assertThat(framed.framed("Mcp-Name", "slow")).isTrue();
        assertThat(framed.framed("Mcp-Name", "slow;payload")).isFalse();
        assertThat(framed.framed("Mcp-Method", "tools/call")).isFalse();
    }

    @Test
    void anUnreadableRecordIsNoRecord() {
        assertThat(FramedOperation.decode("not base64 !")).isEmpty();
        assertThat(FramedOperation.decode(null)).isEmpty();
    }
}
