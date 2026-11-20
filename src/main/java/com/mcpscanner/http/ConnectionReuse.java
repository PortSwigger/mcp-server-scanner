package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

public final class ConnectionReuse {

    static final String CONNECTION_ID = "mcp-scanner";

    private static final Predicate<HttpRequest> NEVER = request -> false;

    private final OriginConnections origins = new OriginConnections();
    private final KeptAliveConnections keptAlive;
    private final Predicate<HttpRequest> answeredLocally;
    private final Predicate<HttpRequest> resendable;

    public ConnectionReuse(Predicate<HttpRequest> answeredLocally) {
        this(answeredLocally, NEVER);
    }

    public ConnectionReuse(Predicate<HttpRequest> answeredLocally, Predicate<HttpRequest> resendable) {
        this(answeredLocally, resendable, Clock.systemUTC());
    }

    ConnectionReuse(Predicate<HttpRequest> answeredLocally, Predicate<HttpRequest> resendable, Clock clock) {
        this.answeredLocally = Objects.requireNonNull(answeredLocally);
        this.resendable = Objects.requireNonNull(resendable);
        this.keptAlive = new KeptAliveConnections(clock);
    }

    public static ConnectionReuse withoutLocalAnswers() {
        return new ConnectionReuse(NEVER);
    }

    public void forgetOrigins() {
        origins.forget();
        keptAlive.forget();
    }

    HttpRequestResponse send(HttpRequest request, SendPath path, ConnectionSender sender) {
        if (answeredLocally.test(request)) {
            return sender.fresh(ConnectionClose.on(request));
        }
        HttpService origin = request.httpService();
        return switch (origins.of(origin)) {
            case UNKNOWN -> learning(origin, sender.fresh(ConnectionClose.on(request)));
            case HTTP_1 -> reusing(path, origin, ConnectionClose.withoutOurs(request), sender);
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

    private HttpRequestResponse reusing(SendPath path, HttpService origin, HttpRequest request,
                                        ConnectionSender sender) {
        Optional<KeptAliveConnections.Lease> lease = keptAlive.take(path, origin);
        if (lease.isEmpty()) {
            return sender.fresh(ConnectionClose.on(request));
        }
        return resentIfUnanswered(request, keptAlive(path, origin, lease.get(), request, sender), sender);
    }

    private HttpRequestResponse resentIfUnanswered(HttpRequest request, HttpRequestResponse exchange,
                                                   ConnectionSender sender) {
        return answered(exchange) || !resendable.test(request) ? exchange : sender.fresh(ConnectionClose.on(request));
    }

    private HttpRequestResponse keptAlive(SendPath path, HttpService origin, KeptAliveConnections.Lease lease,
                                          HttpRequest request, ConnectionSender sender) {
        try {
            HttpRequestResponse exchange = sender.reusing(request, lease.connectionId());
            if (answered(exchange)) {
                keptAlive.putBack(path, origin, lease);
            } else {
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
