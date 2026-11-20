package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.checks.shared.jsonrpc.ReplyBody;

import java.util.Objects;

public record OperationReply(HttpRequestResponse exchange, boolean success, JsonNode result, String signature) {

    private static final String META = "_meta";

    public static OperationReply none() {
        return of(null);
    }

    public static OperationReply of(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null) {
            return new OperationReply(exchange, false, null, "");
        }
        McpReply reply = McpReply.answering(exchange, McpReply::isResponse);
        boolean success = exchange.response().statusCode() / 100 == 2 && reply.successfulResult().isPresent();
        JsonNode result = withoutMeta(reply.result());
        return new OperationReply(exchange, success, result, signature(exchange, reply, result));
    }

    public boolean answered() {
        return exchange != null && exchange.response() != null;
    }

    public boolean accepted() {
        return answered() && exchange.response().statusCode() / 100 == 2;
    }

    public boolean sameResult(OperationReply other) {
        return success && other != null && other.success && Objects.equals(result, other.result);
    }

    public boolean sameReply(OperationReply other) {
        return result != null && other != null && Objects.equals(result, other.result);
    }

    public boolean contains(String marker) {
        return success && !marker.isEmpty() && ReplyBody.text(exchange.response()).contains(marker);
    }

    public boolean substantive() {
        return success && !EmptyContent.empty(result);
    }

    private static JsonNode withoutMeta(JsonNode result) {
        if (!(result instanceof ObjectNode object)) {
            return null;
        }
        ObjectNode copy = object.deepCopy();
        copy.remove(META);
        return copy;
    }

    private static String signature(HttpRequestResponse exchange, McpReply reply, JsonNode result) {
        String status = exchange.response().statusCode() + ":";
        if (result != null) {
            return status + result;
        }
        return reply.answered() ? status + reply.error() : status + ReplyBody.text(exchange.response());
    }
}
