package com.mcpscanner.scan.request;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.JsonSchemaDefaults;

import java.util.List;
import java.util.stream.Stream;

final class ToolCallRequests implements RequestFamilyBuilder {

    @Override
    public RequestFamily family() {
        return RequestFamily.TOOLS_CALL;
    }

    @Override
    public boolean supportedBy(ServerSurface surface) {
        return !surface.inventory().tools().isEmpty();
    }

    @Override
    public List<McpMessage> build(ServerSurface surface) {
        return surface.inventory().tools().stream().flatMap(ToolCallRequests::callsOf).toList();
    }

    private static Stream<McpMessage> callsOf(McpToolDefinition tool) {
        ObjectNode baseArguments = JsonSchemaDefaults.defaultArguments(tool.inputSchema());
        Stream<McpMessage> fieldProbes = JsonSchemaDefaults.withheldArguments(tool.inputSchema()).entrySet().stream()
                .map(withheld -> toolCall(tool, withField(baseArguments, withheld.getKey(), withheld.getValue()))
                        .withAddedArgument(withheld.getKey()));
        return Stream.concat(Stream.of(toolCall(tool, baseArguments)), fieldProbes);
    }

    private static ObjectNode withField(ObjectNode base, ArgumentPath path, JsonNode value) {
        ObjectNode arguments = base.deepCopy();
        path.setIn(arguments, value);
        return arguments;
    }

    private static McpMessage toolCall(McpToolDefinition tool, ObjectNode arguments) {
        ObjectNode params = McpParams.empty().put("name", tool.name());
        params.set("arguments", arguments);
        return McpMessage.namedRequest(RequestFamily.TOOLS_CALL, McpMethods.TOOLS_CALL, McpParams.withMeta(params),
                tool.name());
    }
}
