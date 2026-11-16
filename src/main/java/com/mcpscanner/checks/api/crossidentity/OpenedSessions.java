package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class OpenedSessions {

    private static final String DELETE = "DELETE";
    private static final String CONTENT_TYPE = "Content-Type";

    private final Map<String, HttpRequest> opened = new LinkedHashMap<>();

    public synchronized void record(HttpRequest inSession) {
        SessionHeaders.carriedBy(inSession).ifPresent(sessionId -> opened.putIfAbsent(sessionId, inSession));
    }

    public void deleteAll(Http http, Optional<String> protectedSessionId) {
        drained().stream()
                .filter(request -> !SessionHeaders.carriedBy(request).equals(protectedSessionId))
                .forEach(request -> delete(http, request));
    }

    private synchronized List<HttpRequest> drained() {
        List<HttpRequest> requests = List.copyOf(opened.values());
        opened.clear();
        return requests;
    }

    private static void delete(Http http, HttpRequest inSession) {
        try {
            http.sendRequest(directDelete(inSession));
        } catch (RuntimeException unreachable) {
            return;
        }
    }

    private static HttpRequest directDelete(HttpRequest inSession) {
        return HeaderMutation.apply(inSession, ScannerSentinels.ALL, ScannerSentinels.directDeliveryOnly())
                .withMethod(DELETE).withRemovedHeader(CONTENT_TYPE).withBody("");
    }
}
