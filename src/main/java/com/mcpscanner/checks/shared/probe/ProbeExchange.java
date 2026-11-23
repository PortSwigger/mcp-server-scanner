package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

public record ProbeExchange(List<HttpRequestResponse> exchanges, boolean conclusive) {

    private static final int SERVER_ERROR_STATUS = 500;

    public ProbeExchange {
        exchanges = List.copyOf(exchanges);
        if (exchanges.isEmpty()) {
            throw new IllegalArgumentException("a probe exchange needs at least one exchange");
        }
    }

    public ProbeExchange(List<HttpRequestResponse> exchanges) {
        this(exchanges, true);
    }

    public static ProbeExchange of(HttpRequestResponse... exchanges) {
        return new ProbeExchange(List.of(exchanges));
    }

    public static ProbeExchange interrupted(HttpRequestResponse exchange) {
        return new ProbeExchange(List.of(exchange), false);
    }

    public ProbeExchange followedBy(HttpRequestResponse exchange) {
        List<HttpRequestResponse> followed = new ArrayList<>(exchanges);
        followed.add(exchange);
        return new ProbeExchange(followed, conclusive);
    }

    public HttpRequestResponse last() {
        return exchanges.get(exchanges.size() - 1);
    }

    public HttpRequestResponse answer() {
        HttpRequestResponse probeReply = exchanges.stream()
                .filter(exchange -> !IndependentSessionSender.opensFreshSession(exchange.request()))
                .reduce((earlier, later) -> later)
                .orElseGet(this::last);
        return endsWithRefusedHandshake() && missingSessionOrServerError(probeReply) ? last() : probeReply;
    }

    private boolean endsWithRefusedHandshake() {
        return exchanges.size() > 1 && IndependentSessionSender.opensFreshSession(last().request());
    }

    private static boolean missingSessionOrServerError(HttpRequestResponse exchange) {
        if (exchange.response() == null) {
            return false;
        }
        int status = exchange.response().statusCode();
        return status == IndependentSessionSender.MISSING_SESSION_STATUS || status >= SERVER_ERROR_STATUS;
    }
}
