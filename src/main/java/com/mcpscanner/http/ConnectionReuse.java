package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;
import java.util.function.Predicate;

public final class ConnectionReuse {

    static final String CONNECTION_ID = "mcp-scanner";

    static String connectionIdFor(HttpService origin) {
        return CONNECTION_ID + "-" + OriginConnections.originOf(origin);
    }

    private final OriginConnections origins = new OriginConnections();
    private final Predicate<HttpRequest> answeredLocally;

    public ConnectionReuse(Predicate<HttpRequest> answeredLocally) {
        this.answeredLocally = Objects.requireNonNull(answeredLocally);
    }

    public static ConnectionReuse withoutLocalAnswers() {
        return new ConnectionReuse(request -> false);
    }

    public void forgetOrigins() {
        origins.forget();
    }

    HttpRequestResponse send(HttpRequest request, ConnectionSender sender) {
        if (answeredLocally.test(request)) {
            return sender.fresh(ConnectionClose.on(request));
        }
        HttpService origin = request.httpService();
        return switch (origins.of(origin)) {
            case UNKNOWN -> learning(origin, sender.fresh(ConnectionClose.on(request)));
            case HTTP_1 -> reusing(origin, ConnectionClose.withoutOurs(request), sender);
            case HTTP_2 -> sender.fresh(ConnectionClose.withoutOurs(request));
            case CLOSING -> sender.fresh(ConnectionClose.on(request));
        };
    }

    private HttpRequestResponse learning(HttpService origin, HttpRequestResponse exchange) {
        if (answered(exchange)) {
            origins.learn(origin, exchange.response());
        }
        return exchange;
    }

    private HttpRequestResponse reusing(HttpService origin, HttpRequest request, ConnectionSender sender) {
        try {
            HttpRequestResponse exchange = sender.reusing(request, connectionIdFor(origin));
            if (!answered(exchange)) {
                origins.reuseFailed(origin);
            }
            return exchange;
        } catch (RuntimeException failure) {
            origins.reuseFailed(origin);
            throw failure;
        }
    }

    private static boolean answered(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null && !EmptyResponse.is(exchange.response());
    }
}
