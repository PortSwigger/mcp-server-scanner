package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class McpProtocolVersionsTest {

    @Test
    void scannerPinsToOlderSpecLockedVersion() {
        assertThat(McpProtocolVersions.SCANNER).isEqualTo("2024-11-05");
    }
}
