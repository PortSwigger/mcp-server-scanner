package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.scan.JsonSchemaPredicates;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

final class ToolArgumentFinder {

    private ToolArgumentFinder() {}

    static List<ToolArgument> findArguments(List<DiscoveredTool> tools,
                                            ArgumentHeuristic heuristic) {
        List<ToolArgument> arguments = new ArrayList<>();
        for (DiscoveredTool tool : tools) {
            JsonNode rootSchema = tool.inputSchema();
            JsonNode properties = rootSchema.path("properties");
            if (!properties.isObject()) {
                continue;
            }
            for (Iterator<String> it = properties.fieldNames(); it.hasNext(); ) {
                String propertyName = it.next();
                JsonNode schema = properties.path(propertyName);
                if (!JsonSchemaPredicates.isStringSchema(schema, rootSchema)) {
                    continue;
                }
                String description = schema.path("description").isTextual()
                        ? schema.path("description").asText()
                        : null;
                if (heuristic.matches(propertyName, description)) {
                    arguments.add(new ToolArgument(tool, propertyName));
                }
            }
        }
        return arguments;
    }
}
