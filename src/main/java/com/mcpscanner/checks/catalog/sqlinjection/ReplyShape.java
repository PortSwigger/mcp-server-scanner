package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

final class ReplyShape {

    private static final ReplyShape UNANSWERED = new ReplyShape(Optional.empty());
    private static final List<String> ENVELOPE_MEMBERS = List.of("id", "jsonrpc");

    private final Optional<String> canonical;

    private ReplyShape(Optional<String> canonical) {
        this.canonical = canonical;
    }

    static ReplyShape of(HttpRequestResponse exchange, List<Reflection> reflections) {
        if (exchange == null || exchange.response() == null || TooManyRequests.answered(exchange)) {
            return UNANSWERED;
        }
        return McpReply.answering(exchange, McpReply::isResponse).message()
                .map(message -> new ReplyShape(Optional.of(exchange.response().statusCode() + " "
                        + undone(withoutEnvelope(message), reflections))))
                .orElse(UNANSWERED);
    }

    boolean answered() {
        return canonical.isPresent();
    }

    boolean matches(ReplyShape other) {
        return answered() && Objects.equals(canonical, other.canonical);
    }

    boolean differsFrom(ReplyShape other) {
        return answered() && other.answered() && !matches(other);
    }

    private static JsonNode withoutEnvelope(JsonNode message) {
        ObjectNode copy = message.deepCopy();
        copy.remove(ENVELOPE_MEMBERS);
        return copy;
    }

    private static JsonNode undone(JsonNode node, List<Reflection> reflections) {
        if (node.isTextual()) {
            return JsonNodeFactory.instance.textNode(undone(node.textValue(), reflections));
        }
        if (node.isObject()) {
            ObjectNode copy = JsonNodeFactory.instance.objectNode();
            node.properties().forEach(member -> copy.set(member.getKey(), undone(member.getValue(), reflections)));
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> copy.add(undone(element, reflections)));
            return copy;
        }
        return node;
    }

    private static String undone(String text, List<Reflection> reflections) {
        String result = text;
        for (Reflection reflection : reflections) {
            result = reflection.undo(result);
        }
        return result;
    }
}
