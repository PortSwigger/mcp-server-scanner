package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OwnedArgumentsTest {

    private static final String SCHEMA = "{\"type\":\"object\",\"properties\":{"
            + "\"doc_id\":{\"type\":\"string\"},\"page\":{\"type\":\"integer\"},\"query\":{\"type\":\"string\","
            + "\"default\":\"all\"}},\"required\":[\"doc_id\"]}";

    @Test
    void ownedObjectBecomesTheDefaultOfTheArgumentWithItsName() throws Exception {
        McpToolDefinition tool = OwnedArguments.apply(new McpToolDefinition("get_document", "", SCHEMA),
                Map.of("doc_id", "d-alice-0001"));

        JsonNode properties = McpObjectMapper.INSTANCE.readTree(tool.inputSchema()).path("properties");
        assertThat(properties.path("doc_id").path("default").asText()).isEqualTo("d-alice-0001");
        assertThat(properties.path("query").path("default").asText()).isEqualTo("all");
        assertThat(properties.path("page").has("default")).isFalse();
    }

    @Test
    void aBlankOwnedValueLeavesTheArgumentToTheSynthesisedPlaceholder() throws Exception {
        McpToolDefinition tool = OwnedArguments.apply(new McpToolDefinition("get_document", "", SCHEMA),
                Map.of("doc_id", "  "));

        assertThat(JsonSchemaDefaults.requiredArguments(tool.inputSchema()).path("doc_id").asText())
                .isEqualTo("test");
    }

    @Test
    void numericArgumentsKeepANumericOwnedValue() throws Exception {
        McpToolDefinition tool = OwnedArguments.apply(new McpToolDefinition("get_document", "", SCHEMA),
                Map.of("page", "7"));

        JsonNode page = McpObjectMapper.INSTANCE.readTree(tool.inputSchema()).path("properties").path("page");
        assertThat(page.path("default").isNumber()).isTrue();
        assertThat(page.path("default").asInt()).isEqualTo(7);
    }

    @Test
    void toolsWithoutMatchingArgumentsOrWithAnUnreadableSchemaAreUnchanged() {
        McpToolDefinition plain = new McpToolDefinition("whoami", "", "{\"type\":\"object\",\"properties\":{}}");
        McpToolDefinition broken = new McpToolDefinition("broken", "", "{not json");

        assertThat(OwnedArguments.apply(plain, Map.of("doc_id", "x"))).isSameAs(plain);
        assertThat(OwnedArguments.apply(broken, Map.of("doc_id", "x"))).isSameAs(broken);
        assertThat(OwnedArguments.apply(plain, Map.of())).isSameAs(plain);
    }

    @Test
    void anObjectArrayArgumentGetsTheOwnedArrayFittedToItsItemSchema() throws Exception {
        String schema = "{\"type\":\"object\",\"properties\":{\"files\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
                + "\"properties\":{\"path\":{\"type\":[\"string\",\"null\"]},\"mimeType\":{\"type\":[\"string\",\"null\"]},"
                + "\"url\":{\"type\":[\"string\",\"null\"]}}}}},\"required\":[\"files\"]}";

        McpToolDefinition tool = OwnedArguments.apply(new McpToolDefinition("readAttachment", "", schema),
                Map.of("files", "[{\"path\":\"download/a.txt\",\"mimetype\":\"text/plain\",\"id\":\"x\"}]"));

        assertThat(JsonSchemaDefaults.requiredArguments(tool.inputSchema()).path("files")).isEqualTo(McpObjectMapper.INSTANCE
                .readTree("[{\"path\":\"download/a.txt\",\"mimeType\":\"text/plain\",\"url\":null}]"));
    }
}
