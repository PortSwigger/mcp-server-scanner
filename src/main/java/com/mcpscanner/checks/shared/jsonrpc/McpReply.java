package com.mcpscanner.checks.shared.jsonrpc;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.Optional;
import java.util.function.Predicate;

public final class McpReply {

    private static final McpReply NONE = new McpReply(Optional.empty());

    private final Optional<JsonNode> message;

    private McpReply(Optional<JsonNode> message) {
        this.message = message;
    }

    public static McpReply none() {
        return NONE;
    }

    public static McpReply in(HttpResponse response) {
        if (response == null) {
            return NONE;
        }
        String body = McpRequestDetector.jsonRpcBody(response.headerValue("Content-Type"), ReplyBody.text(response));
        return new McpReply(JsonRpcMessages.parsed(body).filter(JsonNode::isObject));
    }

    public static McpReply of(HttpRequestResponse exchange) {
        if (exchange == null) {
            return NONE;
        }
        McpReply matching = answering(exchange, McpReply::isReply);
        return matching.answered() ? matching : in(exchange.response());
    }

    public static McpReply answering(HttpRequestResponse exchange, Predicate<JsonNode> eligible) {
        if (exchange == null || exchange.response() == null) {
            return NONE;
        }
        JsonRpcEnvelope request = JsonRpcEnvelope.of(exchange.request());
        return new McpReply(JsonRpcMessages.in(ReplyBody.text(exchange.response())).stream()
                .filter(request::isAnsweredBy)
                .filter(eligible)
                .findFirst());
    }

    public static boolean isResponse(JsonNode message) {
        return message.has("result") || message.has("error");
    }

    private static boolean isReply(JsonNode message) {
        return isResponse(message) && !message.has("method");
    }

    public Optional<JsonNode> message() {
        return message;
    }

    public boolean answered() {
        return message.filter(McpReply::isResponse).isPresent();
    }

    public JsonNode result() {
        return member("result");
    }

    public JsonNode error() {
        return member("error");
    }

    public int errorCode() {
        return error().path("code").asInt();
    }

    public boolean toolError() {
        return result().path("isError").asBoolean(false);
    }

    public Optional<JsonNode> successfulResult() {
        boolean succeeded = error().isMissingNode() && result().isObject() && !toolError();
        return succeeded ? Optional.of(result()) : Optional.empty();
    }

    private JsonNode member(String name) {
        return message.map(node -> node.path(name)).orElse(MissingNode.getInstance());
    }
}
