package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequiredArgumentsTest {

    private static final String SCHEMA = "{\"type\":\"object\",\"properties\":{\"tableId\":{\"type\":\"string\"},"
            + "\"where\":{\"type\":\"string\"},\"fields\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
            + "\"pageSize\":{\"type\":\"number\",\"default\":50}},\"required\":[\"tableId\"]}";

    @Test
    void leavesOnlyRequiredAndDefaultedArgumentsToTheGeneratedCall() throws Exception {
        McpToolDefinition tool = RequiredArguments.only(new McpToolDefinition("queryRecords", "", SCHEMA));

        assertThat(properties(tool).fieldNames()).toIterable().containsExactly("tableId", "pageSize");
        assertThat(JsonSchemaDefaults.defaultArguments(tool.inputSchema()).has("where")).isFalse();
    }

    @Test
    void anUnreadableSchemaIsUnchanged() {
        McpToolDefinition broken = new McpToolDefinition("broken", "", "{not json");

        assertThat(RequiredArguments.only(broken)).isSameAs(broken);
    }

    private static JsonNode properties(McpToolDefinition tool) throws Exception {
        return McpObjectMapper.INSTANCE.readTree(tool.inputSchema()).path("properties");
    }
}
