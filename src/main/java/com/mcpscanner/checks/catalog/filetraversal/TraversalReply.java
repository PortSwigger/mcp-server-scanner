package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

import java.util.List;

record TraversalReply(boolean answered, boolean failed, boolean methodNotFound, List<String> texts) {

    private static final int METHOD_NOT_FOUND = -32601;
    private static final TraversalReply UNANSWERED = new TraversalReply(false, false, false, List.of());

    static TraversalReply of(HttpRequestResponse exchange) {
        return exchange == null ? UNANSWERED : of(McpReply.of(exchange));
    }

    private static TraversalReply of(McpReply reply) {
        if (!reply.answered()) {
            return UNANSWERED;
        }
        boolean failed = reply.error().isObject() || reply.toolError();
        boolean methodNotFound = reply.errorCode() == METHOD_NOT_FOUND;
        List<String> texts = ReplyTexts.collect(List.of(reply.result(), reply.error()));
        return new TraversalReply(true, failed, methodNotFound, texts);
    }

    String joinedText() {
        return String.join("\n", texts);
    }

    boolean rejected() {
        String text = joinedText();
        return answered && !methodNotFound
                && (FilesystemMessages.isDenial(text) || failed && !FilesystemMessages.isNotFound(text));
    }
}
