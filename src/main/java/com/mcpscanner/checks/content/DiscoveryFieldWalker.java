package com.mcpscanner.checks.content;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class DiscoveryFieldWalker {

    private static final String SERVER_INFO_OBJECT_NAME = "(initialize)";

    private DiscoveryFieldWalker() {}

    public static List<InspectedField> walk(DiscoveredContent content) {
        if (content == null) {
            return List.of();
        }
        List<InspectedField> fields = new ArrayList<>();
        addServerInfoFields(content.serverInfo(), fields);
        for (McpToolDefinition tool : content.tools()) {
            addToolFields(tool, fields);
        }
        for (McpResourceDefinition resource : content.resources()) {
            addResourceFields(resource, fields);
        }
        for (McpResourceTemplateDefinition template : content.resourceTemplates()) {
            addResourceTemplateFields(template, fields);
        }
        for (McpPromptDefinition prompt : content.prompts()) {
            addPromptFields(prompt, fields);
        }
        return fields;
    }

    private static void addServerInfoFields(ServerMetadata metadata, List<InspectedField> sink) {
        if (metadata == null) {
            return;
        }
        Map<String, String> info = metadata.serverInfo();
        if (info != null) {
            addIfPresent(sink, SourceObjectType.SERVER_INFO, SERVER_INFO_OBJECT_NAME, "name", info.get("name"));
            addIfPresent(sink, SourceObjectType.SERVER_INFO, SERVER_INFO_OBJECT_NAME, "version", info.get("version"));
            addIfPresent(sink, SourceObjectType.SERVER_INFO, SERVER_INFO_OBJECT_NAME, "title", info.get("title"));
        }
        addIfPresent(sink, SourceObjectType.SERVER_INFO, SERVER_INFO_OBJECT_NAME, "instructions", metadata.instructions());
        Map<String, Object> capabilities = metadata.capabilities();
        if (capabilities != null) {
            for (String key : capabilities.keySet()) {
                addIfPresent(sink, SourceObjectType.SERVER_INFO, SERVER_INFO_OBJECT_NAME,
                        "capabilities[" + key + "]", key);
            }
        }
    }

    private static void addToolFields(McpToolDefinition tool, List<InspectedField> sink) {
        String name = tool.name();
        addIfPresent(sink, SourceObjectType.TOOL, name, "name", name);
        addIfPresent(sink, SourceObjectType.TOOL, name, "description", tool.description());
        addInputSchemaFields(tool.inputSchema(), name, sink);
    }

    private static void addInputSchemaFields(String schemaJson, String toolName, List<InspectedField> sink) {
        if (schemaJson == null || schemaJson.isBlank()) {
            return;
        }
        JsonNode root;
        try {
            root = McpObjectMapper.INSTANCE.readTree(schemaJson);
        } catch (Exception ignored) {
            return;
        }
        addIfPresent(sink, SourceObjectType.TOOL, toolName, "inputSchema.description",
                textOrNull(root, "description"));
        JsonNode properties = root.path("properties");
        if (!properties.isObject()) {
            return;
        }
        Iterator<Map.Entry<String, JsonNode>> entries = properties.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            addPropertyFields(entry.getKey(), entry.getValue(), toolName, sink);
        }
    }

    private static void addPropertyFields(String propertyName, JsonNode property, String toolName,
                                          List<InspectedField> sink) {
        if (!property.isObject()) {
            return;
        }
        String basePath = "inputSchema.properties." + propertyName;
        addIfPresent(sink, SourceObjectType.TOOL, toolName, basePath + ".description",
                textOrNull(property, "description"));
        addIfPresent(sink, SourceObjectType.TOOL, toolName, basePath + ".example",
                textOrNull(property, "example"));
        addIfPresent(sink, SourceObjectType.TOOL, toolName, basePath + ".default",
                textOrNull(property, "default"));
        addTextualArrayFields(property.path("examples"), basePath + ".examples", toolName, sink);
        addTextualArrayFields(property.path("enum"), basePath + ".enum", toolName, sink);
    }

    private static void addTextualArrayFields(JsonNode arrayNode, String basePath, String toolName,
                                              List<InspectedField> sink) {
        if (!arrayNode.isArray()) {
            return;
        }
        for (int i = 0; i < arrayNode.size(); i++) {
            JsonNode entry = arrayNode.get(i);
            String value = entry.isTextual() ? entry.asText() : null;
            addIfPresent(sink, SourceObjectType.TOOL, toolName, basePath + "[" + i + "]", value);
        }
    }

    private static void addResourceFields(McpResourceDefinition resource, List<InspectedField> sink) {
        String name = resource.name();
        addIfPresent(sink, SourceObjectType.RESOURCE, name, "name", name);
        addIfPresent(sink, SourceObjectType.RESOURCE, name, "description", resource.description());
        addIfPresent(sink, SourceObjectType.RESOURCE, name, "uri", resource.uri());
        addIfPresent(sink, SourceObjectType.RESOURCE, name, "mimeType", resource.mimeType());
    }

    private static void addResourceTemplateFields(McpResourceTemplateDefinition template,
                                                  List<InspectedField> sink) {
        String name = template.name();
        addIfPresent(sink, SourceObjectType.RESOURCE_TEMPLATE, name, "name", name);
        addIfPresent(sink, SourceObjectType.RESOURCE_TEMPLATE, name, "description", template.description());
        addIfPresent(sink, SourceObjectType.RESOURCE_TEMPLATE, name, "uriTemplate", template.uriTemplate());
    }

    private static void addPromptFields(McpPromptDefinition prompt, List<InspectedField> sink) {
        String name = prompt.name();
        addIfPresent(sink, SourceObjectType.PROMPT, name, "name", name);
        addIfPresent(sink, SourceObjectType.PROMPT, name, "description", prompt.description());
        List<PromptArgument> arguments = prompt.arguments();
        if (arguments == null) {
            return;
        }
        for (int i = 0; i < arguments.size(); i++) {
            PromptArgument argument = arguments.get(i);
            addIfPresent(sink, SourceObjectType.PROMPT, name,
                    "arguments[" + i + "].description", argument.description());
        }
    }

    private static void addIfPresent(List<InspectedField> sink, SourceObjectType type,
                                     String objectName, String fieldPath, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        sink.add(new InspectedField(type, objectName, fieldPath, value));
    }

    private static String textOrNull(JsonNode parent, String field) {
        JsonNode node = parent.path(field);
        return node.isTextual() ? node.asText() : null;
    }
}
