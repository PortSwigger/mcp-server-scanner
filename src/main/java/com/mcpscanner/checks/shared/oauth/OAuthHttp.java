package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.http.EmptyResponse;
import com.mcpscanner.http.OutsideScanQueue;
import com.mcpscanner.mcp.BurpStreamingRefusal;
import com.mcpscanner.mcp.TooManyRequests;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public final class OAuthHttp {

    private static final String APPLICATION_JSON = "application/json";

    public enum NoAnswer {
        RATE_LIMITED,
        STREAMED_REPLY,
        NO_RESPONSE
    }

    private final Http http;
    private final AtomicReference<HttpResponse> rateLimitReply = new AtomicReference<>();
    private final AtomicReference<NoAnswer> missedSinceLastSuccess = new AtomicReference<>();

    public OAuthHttp(Http http) {
        this.http = http;
    }

    public boolean rateLimited() {
        return rateLimitReply.get() != null;
    }

    public Optional<NoAnswer> noAnswer() {
        return rateLimited() ? Optional.of(NoAnswer.RATE_LIMITED) : Optional.ofNullable(missedSinceLastSuccess.get());
    }

    Optional<HttpResponse> rateLimitReply() {
        return Optional.ofNullable(rateLimitReply.get());
    }

    public Optional<HttpRequestResponse> get(URI url, String accept) {
        return get(url, accept, Map.of());
    }

    public Optional<HttpRequestResponse> get(URI url, String accept, Map<String, String> extraHeaders) {
        return send(withHeaders(BareRequests.fromUrl(url.toString()).withAddedHeader("Accept", accept),
                extraHeaders));
    }

    public Optional<HttpRequestResponse> getJson(URI url) {
        return get(url, APPLICATION_JSON);
    }

    public Optional<JsonDocument> getJsonDocument(URI url) {
        return getJson(url).flatMap(JsonDocument::fromSuccessfulResponse);
    }

    public Optional<HttpRequestResponse> postJson(URI url, String body) {
        return send(BareRequests.fromUrl(url.toString())
                .withMethod("POST")
                .withAddedHeader("Content-Type", APPLICATION_JSON)
                .withAddedHeader("Accept", APPLICATION_JSON)
                .withBody(body));
    }

    public Optional<HttpRequestResponse> postForm(URI url, String form, String accept,
                                                  Map<String, String> extraHeaders) {
        return send(withHeaders(BareRequests.fromUrl(url.toString())
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withAddedHeader("Accept", accept)
                .withBody(form), extraHeaders));
    }

    public Optional<HttpRequestResponse> delete(URI url, Map<String, String> extraHeaders) {
        return send(withHeaders(BareRequests.fromUrl(url.toString()).withMethod("DELETE"), extraHeaders));
    }

    public Optional<HttpRequestResponse> send(HttpRequest request) {
        if (rateLimited()) {
            return Optional.empty();
        }
        try {
            return answered(exchange(http, request));
        } catch (RuntimeException failure) {
            if (BurpStreamingRefusal.refused(failure)) {
                return missed(NoAnswer.STREAMED_REPLY);
            }
            throw failure;
        }
    }

    public static HttpRequestResponse exchange(Http http, HttpRequest request) {
        return OutsideScanQueue.send(http, request);
    }

    Optional<HttpRequestResponse> answered(HttpRequestResponse exchange) {
        if (unanswered(exchange)) {
            return missed(NoAnswer.NO_RESPONSE);
        }
        if (TooManyRequests.is(exchange.response())) {
            rateLimitReply.compareAndSet(null, exchange.response());
            return Optional.empty();
        }
        if (exchange.response().statusCode() / 100 == 2) {
            missedSinceLastSuccess.set(null);
        }
        return Optional.of(exchange);
    }

    private static boolean unanswered(HttpRequestResponse exchange) {
        return exchange == null || exchange.response() == null || EmptyResponse.is(exchange.response());
    }

    private Optional<HttpRequestResponse> missed(NoAnswer reason) {
        missedSinceLastSuccess.compareAndSet(null, reason);
        return Optional.empty();
    }

    private static HttpRequest withHeaders(HttpRequest request, Map<String, String> extraHeaders) {
        HttpRequest withExtras = request;
        for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
            withExtras = withExtras.withAddedHeader(header.getKey(), header.getValue());
        }
        return withExtras;
    }
}
