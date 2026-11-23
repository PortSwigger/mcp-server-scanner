package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.checks.shared.jsonrpc.ReplyBody;

import java.util.Optional;

final class ReplySignature {

    private static final int OK = 200;

    private final PayloadMask mask;
    private final TimingValues timings = new TimingValues();

    ReplySignature(PayloadMask mask) {
        this.mask = mask;
    }

    Optional<String> ofSuccess(HttpRequestResponse exchange, String payload) {
        HttpResponse response = exchange.response();
        if (response == null || response.statusCode() != OK) {
            return Optional.empty();
        }
        return McpReply.in(response).message()
                .map(root -> root.path("result"))
                .filter(result -> result.isObject() && !result.path("isError").asBoolean(false))
                .map(result -> mask.mask(timings.mask(withoutMeta(result).toString()), payload));
    }

    String of(HttpRequestResponse exchange, String payload) {
        return ofSuccess(exchange, payload).orElseGet(() -> ofFailure(exchange.response(), payload));
    }

    private String ofFailure(HttpResponse response, String payload) {
        if (response == null) {
            return "no-response";
        }
        String body = McpReply.in(response).message().map(ReplySignature::withoutId).map(JsonNode::toString)
                .orElseGet(() -> ReplyBody.text(response));
        return "failure " + response.statusCode() + ":" + mask.mask(timings.mask(body), payload);
    }

    private static JsonNode withoutId(JsonNode root) {
        ObjectNode copy = root.deepCopy();
        copy.remove("id");
        if (copy.path("result").isObject()) {
            copy.set("result", withoutMeta(copy.path("result")));
        }
        return copy;
    }

    private static JsonNode withoutMeta(JsonNode result) {
        ObjectNode copy = result.deepCopy();
        copy.remove("_meta");
        return copy;
    }
}
