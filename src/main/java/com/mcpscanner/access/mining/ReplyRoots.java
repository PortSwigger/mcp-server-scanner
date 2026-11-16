package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class ReplyRoots {

    private final List<ReplyRoot> roots = new ArrayList<>();

    private ReplyRoots() {
    }

    static List<ReplyRoot> of(JsonNode result) {
        ReplyRoots collected = new ReplyRoots();
        collected.roots.add(new ReplyRoot("structuredContent", result.path("structuredContent")));
        collected.embedded(result.path("content"), "content", "text");
        collected.embedded(result.path("content"), "content", "resource", "text");
        collected.embedded(result.path("contents"), "contents", "text");
        collected.embedded(result.path("messages"), "messages", "content", "text");
        return List.copyOf(collected.roots);
    }

    private void embedded(JsonNode items, String name, String... textPath) {
        for (int index = 0; index < items.size(); index++) {
            JsonNode text = items.get(index);
            for (String step : textPath) {
                text = text.path(step);
            }
            String location = name + "[" + index + "]." + String.join(".", textPath);
            parsed(text).ifPresent(json -> roots.add(new ReplyRoot(location, json)));
        }
    }

    private static Optional<JsonNode> parsed(JsonNode text) {
        if (!text.isTextual()) {
            return Optional.empty();
        }
        try {
            JsonNode json = McpObjectMapper.INSTANCE.readTree(text.asText());
            return json != null && json.isContainerNode() ? Optional.of(json) : Optional.empty();
        } catch (Exception notJson) {
            return Optional.empty();
        }
    }
}
