package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class McpToolDefinitionTest {

    @Test
    void recordAccessorsReturnConstructorValues() {
        McpToolDefinition tool = new McpToolDefinition("myTool", "A description", "{\"type\":\"object\"}");

        assertThat(tool.name()).isEqualTo("myTool");
        assertThat(tool.description()).isEqualTo("A description");
        assertThat(tool.inputSchema()).isEqualTo("{\"type\":\"object\"}");
    }

    @Test
    void hasPropertiesReturnsTrueWhenSchemaContainsProperties() {
        String schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}";

        McpToolDefinition tool = new McpToolDefinition("tool", "desc", schema);

        assertThat(tool.hasProperties()).isTrue();
    }

    @Test
    void hasPropertiesReturnsFalseWhenSchemaLacksProperties() {
        String schema = "{\"type\":\"object\"}";

        McpToolDefinition tool = new McpToolDefinition("tool", "desc", schema);

        assertThat(tool.hasProperties()).isFalse();
    }

    @Test
    void hasPropertiesReturnsFalseForEmptySchema() {
        McpToolDefinition tool = new McpToolDefinition("tool", "desc", "{}");

        assertThat(tool.hasProperties()).isFalse();
    }

    @Test
    void hasPropertiesReturnsFalseForNullSchema() {
        McpToolDefinition tool = new McpToolDefinition("tool", "desc", null);

        assertThat(tool.hasProperties()).isFalse();
    }

    @Test
    void hasPropertiesReturnsFalseForEmptyStringSchema() {
        McpToolDefinition tool = new McpToolDefinition("tool", "desc", "");

        assertThat(tool.hasProperties()).isFalse();
    }

    @Test
    void hasPropertiesReturnsFalseWhenPropertiesAppearsOnlyInValue() {
        String schema = "{\"type\":\"object\",\"description\":\"has properties in description\"}";

        McpToolDefinition tool = new McpToolDefinition("tool", "desc", schema);

        assertThat(tool.hasProperties()).isFalse();
    }
}
