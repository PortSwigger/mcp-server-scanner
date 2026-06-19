package com.mcpscanner.checks.content;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpRequestDetector.DiscoveryResponseKind;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Field-scoped translator from a JSON-RPC discovery response body to a {@link DiscoveredContent}
 * the {@link ContentRuleEngine} can run rules against.
 *
 * <p>Crucial FP guardrail: this translator populates ONLY the MCP-spec-defined textual
 * fields the rules are allowed to inspect — tool/resource/prompt {@code name},
 * {@code title}, {@code description}, {@code mimeType}, {@code uri}, and {@code icons[]} —
 * plus {@code serverInfo} for initialize. It deliberately leaves {@code inputSchema} as
 * {@code null} and prompt {@code arguments} empty so the downstream
 * {@link DiscoveryFieldWalker} cannot walk into argument schema {@code default}s or other
 * user-controlled tool configuration metadata that may legitimately contain
 * placeholder-shaped strings.
 */
public final class JsonRpcDiscoveredContentTranslator {

    private JsonRpcDiscoveredContentTranslator() {}

    public static DiscoveredContent translate(DiscoveryResponseKind kind, String responseBody) {
        if (kind == null || kind == DiscoveryResponseKind.OTHER || responseBody == null) {
            return empty();
        }
        JsonNode result = parseResult(responseBody);
        if (result == null) {
            return empty();
        }
        return switch (kind) {
            case TOOLS_LIST -> new DiscoveredContent(
                    ServerMetadata.empty(), parseTools(result), List.of(), List.of(), List.of());
            case RESOURCES_LIST -> new DiscoveredContent(
                    ServerMetadata.empty(), List.of(), parseResources(result), List.of(), List.of());
            case PROMPTS_LIST -> new DiscoveredContent(
                    ServerMetadata.empty(), List.of(), List.of(), List.of(), parsePrompts(result));
            case INITIALIZE -> new DiscoveredContent(
                    parseServerMetadata(result), List.of(), List.of(), List.of(), List.of());
            default -> empty();
        };
    }

    private static DiscoveredContent empty() {
        return new DiscoveredContent(ServerMetadata.empty(),
                List.of(), List.of(), List.of(), List.of());
    }

    private static JsonNode parseResult(String body) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            JsonNode result = root.path("result");
            return result.isObject() ? result : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static List<McpToolDefinition> parseTools(JsonNode result) {
        List<McpToolDefinition> tools = new ArrayList<>();
        for (JsonNode tool : result.path("tools")) {
            tools.add(new McpToolDefinition(
                    textOrEmpty(tool, "name"),
                    descriptionWithTitle(tool),
                    null,
                    parseIcons(tool.path("icons"))));
        }
        return tools;
    }

    private static List<McpResourceDefinition> parseResources(JsonNode result) {
        List<McpResourceDefinition> resources = new ArrayList<>();
        for (JsonNode resource : result.path("resources")) {
            resources.add(new McpResourceDefinition(
                    textOrEmpty(resource, "uri"),
                    textOrEmpty(resource, "name"),
                    descriptionWithTitle(resource),
                    textOrEmpty(resource, "mimeType"),
                    parseIcons(resource.path("icons"))));
        }
        return resources;
    }

    private static List<McpPromptDefinition> parsePrompts(JsonNode result) {
        List<McpPromptDefinition> prompts = new ArrayList<>();
        for (JsonNode prompt : result.path("prompts")) {
            prompts.add(new McpPromptDefinition(
                    textOrEmpty(prompt, "name"),
                    descriptionWithTitle(prompt),
                    List.of(),
                    parseIcons(prompt.path("icons"))));
        }
        return prompts;
    }

    private static ServerMetadata parseServerMetadata(JsonNode result) {
        JsonNode serverInfo = result.path("serverInfo");
        Map<String, String> info = new LinkedHashMap<>();
        if (serverInfo.isObject()) {
            putIfText(info, serverInfo, "name");
            putIfText(info, serverInfo, "title");
            putIfText(info, serverInfo, "version");
        }
        String instructions = textOrEmpty(result, "instructions");
        Map<String, Object> capabilities = capabilityKeys(result.path("capabilities"));
        return new ServerMetadata(info, instructions, capabilities, parseIcons(serverInfo.path("icons")));
    }

    private static Map<String, Object> capabilityKeys(JsonNode capabilitiesNode) {
        if (!capabilitiesNode.isObject()) {
            return Map.of();
        }
        Map<String, Object> capabilities = new LinkedHashMap<>();
        capabilitiesNode.fieldNames().forEachRemaining(name -> capabilities.put(name, true));
        return capabilities;
    }

    private static List<IconDescriptor> parseIcons(JsonNode iconsNode) {
        if (!iconsNode.isArray()) {
            return List.of();
        }
        List<IconDescriptor> icons = new ArrayList<>(iconsNode.size());
        for (JsonNode icon : iconsNode) {
            icons.add(new IconDescriptor(
                    textOrNull(icon, "src"),
                    textOrNull(icon, "mimeType"),
                    readSizes(icon.path("sizes"))));
        }
        return icons;
    }

    private static List<String> readSizes(JsonNode sizesNode) {
        if (!sizesNode.isArray()) {
            return List.of();
        }
        List<String> sizes = new ArrayList<>(sizesNode.size());
        for (JsonNode size : sizesNode) {
            if (size.isTextual()) {
                sizes.add(size.asText());
            }
        }
        return sizes;
    }

    private static String descriptionWithTitle(JsonNode node) {
        String title = textOrNull(node, "title");
        String description = textOrNull(node, "description");
        if (title == null) return description == null ? "" : description;
        if (description == null) return title;
        return title + "\n" + description;
    }

    private static void putIfText(Map<String, String> sink, JsonNode parent, String field) {
        String value = textOrNull(parent, field);
        if (value != null) sink.put(field, value);
    }

    private static String textOrEmpty(JsonNode parent, String field) {
        String value = textOrNull(parent, field);
        return value == null ? "" : value;
    }

    private static String textOrNull(JsonNode parent, String field) {
        JsonNode node = parent.path(field);
        return node.isTextual() ? node.asText() : null;
    }
}
