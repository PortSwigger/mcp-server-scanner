package com.mcpscanner.checks.shared.stream;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.Locale;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;

public record StreamOpening(HttpRequestResponse exchange, boolean heldOpen, boolean sent) {

    private static final Set<Integer> TRANSIENT_REFUSALS = Set.of(408, 425, TooManyRequests.STATUS);

    public StreamOpening(HttpRequestResponse exchange, boolean heldOpen) {
        this(exchange, heldOpen, true);
    }

    static StreamOpening unanswered(HttpRequest request) {
        return new StreamOpening(HttpRequestResponse.httpRequestResponse(request, null), false);
    }

    static StreamOpening unanswered(WireRecord sent) {
        return new StreamOpening(sent.evidence(), false);
    }

    static StreamOpening unsent(HttpRequest request) {
        return new StreamOpening(HttpRequestResponse.httpRequestResponse(request, null), false, false);
    }

    public boolean answered() {
        return exchange.response() != null;
    }

    public OptionalInt status() {
        return answered() ? OptionalInt.of(exchange.response().statusCode()) : OptionalInt.empty();
    }

    public boolean opened() {
        return heldOpen && successful() && eventStream();
    }

    public boolean rejected() {
        int status = status().orElse(0);
        return status >= 400 && status < 500 && !TRANSIENT_REFUSALS.contains(status);
    }

    public boolean transientFailure() {
        int status = status().orElse(0);
        return !answered() || TRANSIENT_REFUSALS.contains(status) || status >= 500;
    }

    private boolean successful() {
        int status = status().orElse(0);
        return status >= 200 && status < 300;
    }

    private boolean eventStream() {
        return Optional.ofNullable(exchange.response()).map(response -> response.headerValue("Content-Type"))
                .map(type -> type.toLowerCase(Locale.ROOT).startsWith(StreamGetRequest.EVENT_STREAM))
                .orElse(false);
    }

    static StreamOpening answered(WireRecord exchange, boolean heldOpen) {
        return new StreamOpening(exchange.evidence(), heldOpen);
    }
}
