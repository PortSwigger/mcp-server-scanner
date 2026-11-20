package com.mcpscanner.checks.shared.jsonrpc;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.http.BurpMessages;

import java.nio.charset.StandardCharsets;
import java.util.List;

public final class ReplyBody {

    private static final String TRANSFER_ENCODING = "Transfer-Encoding";

    private ReplyBody() {}

    public static String text(HttpResponse response) {
        return response.hasHeader(TRANSFER_ENCODING)
                ? new String(BurpMessages.unframedBody(response), StandardCharsets.UTF_8)
                : response.bodyToString();
    }

    public static boolean sameAnswer(HttpResponse first, HttpResponse second) {
        return first.statusCode() == second.statusCode() && payload(first).equals(payload(second));
    }

    private static String payload(HttpResponse response) {
        String text = text(response);
        List<JsonNode> messages = JsonRpcMessages.in(text);
        return messages.isEmpty() ? text : messages.toString();
    }
}
