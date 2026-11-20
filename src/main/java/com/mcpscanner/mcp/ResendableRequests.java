package com.mcpscanner.mcp;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class ResendableRequests {

    private static final Set<String> READ_METHODS = Set.of(McpMethods.INITIALIZE,
            McpMethods.NOTIFICATIONS_INITIALIZED, McpMethods.PING, McpMethods.SERVER_DISCOVER, McpMethods.TOOLS_LIST,
            McpMethods.RESOURCES_LIST, McpMethods.RESOURCE_TEMPLATES_LIST, McpMethods.PROMPTS_LIST,
            McpMethods.RESOURCES_READ, McpMethods.PROMPTS_GET, McpMethods.COMPLETION_COMPLETE);

    private static final Set<String> SAFE_HTTP_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private volatile Map<String, McpToolDefinition> readOnlyTools = Map.of();

    public void learn(Collection<McpToolDefinition> tools) {
        readOnlyTools = tools.stream()
                .filter(tool -> tool.name() != null && ToolSafety.readsOnly(tool))
                .collect(Collectors.toUnmodifiableMap(McpToolDefinition::name, Function.identity(),
                        (first, second) -> first));
    }

    public void forget() {
        readOnlyTools = Map.of();
    }

    public boolean resendable(String httpMethod, String body) {
        if (body == null || body.isEmpty()) {
            return SAFE_HTTP_METHODS.contains(Objects.requireNonNullElse(httpMethod, "").toUpperCase(Locale.ROOT));
        }
        return resendable(body);
    }

    public boolean resendable(String jsonRpcBody) {
        return parsed(jsonRpcBody).filter(JsonNode::isObject).map(this::reads).orElse(false);
    }

    private boolean reads(JsonNode request) {
        String method = request.path("method").isTextual() ? request.path("method").asText() : "";
        if (McpMethods.TOOLS_CALL.equals(method)) {
            return readOnlyTools.containsKey(request.path("params").path("name").asText(""));
        }
        return READ_METHODS.contains(method);
    }

    private static Optional<JsonNode> parsed(String body) {
        try {
            return Optional.ofNullable(McpObjectMapper.INSTANCE.readTree(Objects.requireNonNullElse(body, "")));
        } catch (Exception unparseable) {
            return Optional.empty();
        }
    }
}
