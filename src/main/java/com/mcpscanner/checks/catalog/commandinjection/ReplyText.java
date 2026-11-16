package com.mcpscanner.checks.catalog.commandinjection;

import com.fasterxml.jackson.databind.JsonNode;

final class ReplyText {

    private ReplyText() {}

    static boolean anyContains(JsonNode node, String text) {
        if (node.isTextual()) {
            return node.textValue().contains(text);
        }
        for (JsonNode child : node) {
            if (anyContains(child, text)) {
                return true;
            }
        }
        return false;
    }

    static String joined(JsonNode node) {
        if (node.isTextual()) {
            return node.textValue();
        }
        StringBuilder text = new StringBuilder();
        node.forEach(child -> text.append(joined(child)).append('\n'));
        return text.toString();
    }

    static boolean contentTextStartsWith(JsonNode result, String prefix) {
        for (JsonNode item : result.path("content")) {
            if (item.path("text").asText("").startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
