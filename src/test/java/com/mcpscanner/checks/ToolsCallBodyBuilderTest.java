package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ToolsCallBodyBuilderTest {

    private static DiscoveredTool tool(String name, String schemaJson) throws Exception {
        JsonNode schema = McpObjectMapper.INSTANCE.readTree(schemaJson);
        return new DiscoveredTool(name, schema);
    }

    @Test
    void buildsJsonRpcEnvelopeWithToolsCallMethodAndPayloadArgument() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\"}}}");
        ToolArgument argument = new ToolArgument(tool, "code");

        String body = ToolsCallBodyBuilder.buildToolsCallBody(argument, "PAYLOAD");

        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(body);
        assertThat(envelope.path("jsonrpc").asText()).isEqualTo("2.0");
        assertThat(envelope.path("id").isNumber() || envelope.path("id").isTextual()).isTrue();
        assertThat(envelope.path("method").asText()).isEqualTo("tools/call");
        assertThat(envelope.path("params").path("name").asText()).isEqualTo("runner");
        assertThat(envelope.path("params").path("arguments").path("code").asText()).isEqualTo("PAYLOAD");
    }

    @Test
    void payloadOverridesSchemaDefaultForTheTargetedArgument() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{"
                        + "\"code\":{\"type\":\"string\",\"default\":\"DEFAULT\"},"
                        + "\"other\":{\"type\":\"string\",\"default\":\"KEEP\"}}}");
        ToolArgument argument = new ToolArgument(tool, "code");

        String body = ToolsCallBodyBuilder.buildToolsCallBody(argument, "PAYLOAD");

        JsonNode arguments = McpObjectMapper.INSTANCE.readTree(body).path("params").path("arguments");
        assertThat(arguments.path("code").asText()).isEqualTo("PAYLOAD");
        assertThat(arguments.path("other").asText()).isEqualTo("KEEP");
    }

    @Test
    void emitsUniqueRequestIdsAcrossCalls() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\"}}}");
        ToolArgument argument = new ToolArgument(tool, "code");

        JsonNode first = McpObjectMapper.INSTANCE.readTree(
                ToolsCallBodyBuilder.buildToolsCallBody(argument, "A"));
        JsonNode second = McpObjectMapper.INSTANCE.readTree(
                ToolsCallBodyBuilder.buildToolsCallBody(argument, "B"));

        assertThat(first.path("id").asText()).isNotEqualTo(second.path("id").asText());
    }
}
