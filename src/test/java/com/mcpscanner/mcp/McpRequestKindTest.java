package com.mcpscanner.mcp;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class McpRequestKindTest {

    @ParameterizedTest
    @EnumSource(value = McpRequestKind.class, mode = EnumSource.Mode.EXCLUDE, names = "NOT_MCP")
    void isMcpReturnsTrueForEveryMcpVariant(McpRequestKind kind) {
        assertThat(kind.isMcp()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = McpRequestKind.class, mode = EnumSource.Mode.INCLUDE, names = "NOT_MCP")
    void isMcpReturnsFalseOnlyForNotMcp(McpRequestKind kind) {
        assertThat(kind.isMcp()).isFalse();
    }
}
