package com.mcpscanner.automation;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Objects;

public final class EvidenceSummary {

    private static final String NO_RESPONSE = "(no response)";

    private EvidenceSummary() {
    }

    public static List<String> of(List<HttpRequestResponse> evidence) {
        return evidence == null ? List.of() : evidence.stream().filter(Objects::nonNull).map(EvidenceSummary::of).toList();
    }

    private static String of(HttpRequestResponse exchange) {
        return firstLine(exchange.request().toByteArray().toString()) + " => " + responseSummary(exchange.response());
    }

    private static String responseSummary(HttpResponse response) {
        if (response == null) {
            return NO_RESPONSE;
        }
        String contentType = response.headerValue("Content-Type");
        String statusLine = firstLine(response.toByteArray().toString());
        return contentType == null ? statusLine : statusLine + " | " + contentType;
    }

    private static String firstLine(String message) {
        int end = message.indexOf("\r\n");
        return end < 0 ? message : message.substring(0, end);
    }
}
