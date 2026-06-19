package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ToolArgumentFinderTest {

    private static final ArgumentHeuristic MATCH_ALL = (name, description) -> true;
    private static final ArgumentHeuristic MATCH_NONE = (name, description) -> false;

    private static DiscoveredTool tool(String name, String schemaJson) throws Exception {
        JsonNode schema = McpObjectMapper.INSTANCE.readTree(schemaJson);
        return new DiscoveredTool(name, schema);
    }

    @Test
    void returnsStringPropertyThatMatchesHeuristic() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\"}}}");

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), MATCH_ALL);

        assertThat(arguments).singleElement()
                .satisfies(argument -> {
                    assertThat(argument.tool()).isEqualTo(tool);
                    assertThat(argument.name()).isEqualTo("code");
                });
    }

    @Test
    void skipsNonStringSchemaProperty() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"integer\"}}}");

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), MATCH_ALL);

        assertThat(arguments).isEmpty();
    }

    @Test
    void skipsToolWithNoPropertiesObject() throws Exception {
        DiscoveredTool tool = tool("runner", "{\"type\":\"object\"}");

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), MATCH_ALL);

        assertThat(arguments).isEmpty();
    }

    @Test
    void heuristicGatesInclusion() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\"}}}");

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), MATCH_NONE);

        assertThat(arguments).isEmpty();
    }

    @Test
    void passesPropertyNameAndDescriptionToHeuristic() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{"
                        + "\"payload\":{\"type\":\"string\",\"description\":\"the command to run\"}}}");
        ArgumentHeuristic onlyByDescription =
                (name, description) -> description != null && description.contains("command to run");

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), onlyByDescription);

        assertThat(arguments).singleElement()
                .satisfies(argument -> assertThat(argument.name()).isEqualTo("payload"));
    }

    @Test
    void passesNullDescriptionWhenSchemaHasNone() throws Exception {
        DiscoveredTool tool = tool("runner",
                "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\"}}}");
        ArgumentHeuristic requiresNullDescription = (name, description) -> description == null;

        List<ToolArgument> arguments = ToolArgumentFinder.findArguments(List.of(tool), requiresNullDescription);

        assertThat(arguments).singleElement()
                .satisfies(argument -> assertThat(argument.name()).isEqualTo("code"));
    }
}
