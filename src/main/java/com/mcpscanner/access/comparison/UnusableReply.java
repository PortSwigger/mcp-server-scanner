package com.mcpscanner.access.comparison;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.shared.jsonrpc.JsonNodes;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

import java.util.stream.Collectors;

final class UnusableReply {

    static final int MAX_DETAIL = 200;

    private UnusableReply() {
    }

    static String describe(OperationReply reply) {
        if (!reply.answered()) {
            return "got no response";
        }
        McpReply mcp = McpReply.answering(reply.exchange(), McpReply::isResponse);
        if (!mcp.error().isMissingNode()) {
            return "returned a JSON-RPC error: " + capped(errorText(mcp.error()));
        }
        if (mcp.toolError()) {
            return "returned isError: " + capped(contentText(mcp.result()));
        }
        if (!reply.accepted()) {
            return "returned HTTP " + reply.exchange().response().statusCode();
        }
        return mcp.answered() ? "returned an empty result" : "returned no JSON-RPC reply";
    }

    private static String errorText(JsonNode error) {
        JsonNode message = error.path("message");
        return message.isTextual() ? message.asText() : error.toString();
    }

    private static String contentText(JsonNode result) {
        String text = JsonNodes.elements(result.path("content")).stream().map(item -> item.path("text"))
                .filter(JsonNode::isTextual).map(JsonNode::asText).collect(Collectors.joining(" "));
        return text.isBlank() ? "(no text)" : text;
    }

    private static String capped(String text) {
        String flat = text.strip().replaceAll("\\s+", " ");
        return flat.length() <= MAX_DETAIL ? flat : flat.substring(0, MAX_DETAIL) + "…";
    }
}
