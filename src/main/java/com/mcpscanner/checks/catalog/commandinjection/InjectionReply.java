package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

import java.util.List;

final class InjectionReply {

    private static final String TOOL_INVOCATION_FAILURE_PREFIX = "Error invoking tool ";

    private final HttpRequestResponse exchange;
    private final McpReply reply;

    private InjectionReply(HttpRequestResponse exchange, McpReply reply) {
        this.exchange = exchange;
        this.reply = reply;
    }

    static InjectionReply of(HttpRequestResponse exchange) {
        McpReply reply = successfulStatus(exchange) ? McpReply.answering(exchange, McpReply::isResponse)
                : McpReply.none();
        return new InjectionReply(exchange, reply);
    }

    HttpRequestResponse exchange() {
        return exchange;
    }

    HttpRequestResponse exchangeHighlighting(List<String> proofs) {
        return PayloadHighlights.ofProof(exchange, proofs);
    }

    boolean answered() {
        return reply.answered();
    }

    boolean successful() {
        return reply.successfulResult().filter(InjectionReply::reportsNoError).isPresent();
    }

    boolean rejected() {
        return answered() && !successful();
    }

    boolean contains(String text) {
        return reply.message().map(node -> ReplyText.anyContains(node, text)).orElse(false);
    }

    String text() {
        return reply.message().map(ReplyText::joined).orElse("");
    }

    private static boolean reportsNoError(JsonNode result) {
        return !result.path("error").asBoolean(false)
                && !ReplyText.contentTextStartsWith(result, TOOL_INVOCATION_FAILURE_PREFIX);
    }

    private static boolean successfulStatus(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null && exchange.response().statusCode() / 100 == 2;
    }
}
