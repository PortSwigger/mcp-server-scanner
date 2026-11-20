package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class OutsideScanQueue {

    private static final ThreadLocal<Boolean> REQUESTED = ThreadLocal.withInitial(() -> false);

    private OutsideScanQueue() {
    }

    public static HttpRequestResponse send(Http http, HttpRequest request) {
        boolean previous = REQUESTED.get();
        REQUESTED.set(true);
        try {
            return http.sendRequest(request);
        } finally {
            REQUESTED.set(previous);
        }
    }

    static boolean requested() {
        return REQUESTED.get();
    }
}
