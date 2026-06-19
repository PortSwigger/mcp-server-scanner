package com.mcpscanner.checks.content;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryFieldWalkerTest {

    @Test
    void returnsEmptyListForNullContent() {
        assertThat(DiscoveryFieldWalker.walk(null)).isEmpty();
    }

    @Test
    void walksServerInfoFields() {
        DiscoveredContent content = new DiscoveredContent(
                new ServerMetadata(
                        Map.of("name", "my-server", "version", "1.2.3"),
                        "These are instructions.",
                        Map.of()),
                List.of(), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(serverInfo("name"))
                .singleElement().extracting(InspectedField::value).isEqualTo("my-server");
        assertThat(fields).filteredOn(serverInfo("version"))
                .singleElement().extracting(InspectedField::value).isEqualTo("1.2.3");
        assertThat(fields).filteredOn(serverInfo("instructions"))
                .singleElement().extracting(InspectedField::value).isEqualTo("These are instructions.");
    }

    @Test
    void walksServerInfoTitle() {
        DiscoveredContent content = new DiscoveredContent(
                new ServerMetadata(
                        Map.of("name", "my-server", "title", "My Server Title", "version", "1.2.3"),
                        "",
                        Map.of()),
                List.of(), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(serverInfo("title"))
                .singleElement().extracting(InspectedField::value).isEqualTo("My Server Title");
    }

    @Test
    void walksCapabilityKeys() {
        DiscoveredContent content = new DiscoveredContent(
                new ServerMetadata(
                        Map.of("name", "my-server"),
                        "",
                        Map.of("tools", Boolean.TRUE, "resources", Boolean.TRUE, "prompts", Boolean.TRUE)),
                List.of(), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.SERVER_INFO
                        && f.fieldPath().startsWith("capabilities["))
                .extracting(InspectedField::fieldPath)
                .containsExactlyInAnyOrder("capabilities[tools]", "capabilities[resources]", "capabilities[prompts]");
    }

    @Test
    void walksResourceMimeType() {
        McpResourceDefinition resource = new McpResourceDefinition(
                "file:///x.json", "manifest", "Some description", "application/json", List.of());
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(), List.of(resource), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.RESOURCE
                        && f.fieldPath().equals("mimeType"))
                .singleElement()
                .satisfies(field -> {
                    assertThat(field.objectName()).isEqualTo("manifest");
                    assertThat(field.value()).isEqualTo("application/json");
                });
    }

    @Test
    void walksToolFieldsIncludingInputSchema() {
        String schema = "{"
                + "\"description\":\"top-level\","
                + "\"properties\":{"
                + "  \"action\":{\"description\":\"what to do\",\"enum\":[\"create\",\"delete\"]}"
                + "}"
                + "}";
        McpToolDefinition tool = new McpToolDefinition("do_thing", "tool description", schema);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields)
                .anyMatch(toolFieldPath("name", "do_thing"))
                .anyMatch(toolFieldPath("description", "tool description"))
                .anyMatch(toolFieldPath("inputSchema.description", "top-level"))
                .anyMatch(toolFieldPath("inputSchema.properties.action.description", "what to do"))
                .anyMatch(toolFieldPath("inputSchema.properties.action.enum[0]", "create"))
                .anyMatch(toolFieldPath("inputSchema.properties.action.enum[1]", "delete"));
    }

    @Test
    void walksInputSchemaExampleExamplesAndDefault() {
        String schema = "{"
                + "\"properties\":{"
                + "  \"token\":{"
                + "    \"description\":\"api token\","
                + "    \"example\":\"sk_live_exampleone\","
                + "    \"examples\":[\"sk_live_exampletwo\",\"sk_live_examplethree\"],"
                + "    \"default\":\"sk_live_defaultvalue\""
                + "  }"
                + "}"
                + "}";
        McpToolDefinition tool = new McpToolDefinition("configure", "tool", schema);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields)
                .anyMatch(toolFieldPath("inputSchema.properties.token.example", "sk_live_exampleone"))
                .anyMatch(toolFieldPath("inputSchema.properties.token.examples[0]", "sk_live_exampletwo"))
                .anyMatch(toolFieldPath("inputSchema.properties.token.examples[1]", "sk_live_examplethree"))
                .anyMatch(toolFieldPath("inputSchema.properties.token.default", "sk_live_defaultvalue"));
    }

    @Test
    void walksResourceFields() {
        McpResourceDefinition resource = new McpResourceDefinition(
                "file:///x", "config", "the config", "text/plain");
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(), List.of(resource), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.RESOURCE)
                .extracting(InspectedField::fieldPath)
                .containsExactlyInAnyOrder("name", "description", "uri", "mimeType");
    }

    @Test
    void walksResourceTemplateFields() {
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "file:///srv/{path}", "templated-file", "Secret AKIA234567ABCDEFGHIJ", "text/plain");
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(), List.of(), List.of(template), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.RESOURCE_TEMPLATE)
                .extracting(InspectedField::fieldPath)
                .containsExactlyInAnyOrder("name", "description", "uriTemplate");
        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.RESOURCE_TEMPLATE
                        && f.fieldPath().equals("description"))
                .singleElement().extracting(InspectedField::value)
                .isEqualTo("Secret AKIA234567ABCDEFGHIJ");
    }

    @Test
    void walksPromptFieldsIncludingArguments() {
        McpPromptDefinition prompt = new McpPromptDefinition(
                "ask", "prompt desc",
                List.of(new PromptArgument("query", "search query", true)));
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(), List.of(), List.of(), List.of(prompt));

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.PROMPT)
                .extracting(InspectedField::fieldPath)
                .containsExactlyInAnyOrder("name", "description", "arguments[0].description");
    }

    @Test
    void skipsNullAndEmptyValues() {
        McpToolDefinition tool = new McpToolDefinition("tool_a", "", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.TOOL)
                .extracting(InspectedField::fieldPath)
                .containsExactly("name");
    }

    @Test
    void tolerantToInvalidInputSchema() {
        McpToolDefinition tool = new McpToolDefinition("bad", "x", "not-json");
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        List<InspectedField> fields = DiscoveryFieldWalker.walk(content);

        assertThat(fields).filteredOn(f -> f.objectType() == SourceObjectType.TOOL)
                .extracting(InspectedField::fieldPath)
                .containsExactlyInAnyOrder("name", "description");
    }

    private static Predicate<InspectedField> serverInfo(String path) {
        return f -> f.objectType() == SourceObjectType.SERVER_INFO && f.fieldPath().equals(path);
    }

    private static Predicate<InspectedField> toolFieldPath(String fieldPath, String value) {
        return f -> f.objectType() == SourceObjectType.TOOL
                && f.fieldPath().equals(fieldPath)
                && f.value().equals(value);
    }
}
