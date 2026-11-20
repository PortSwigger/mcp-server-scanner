package com.mcpscanner.checks.api;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.mcpscanner.http.ForwardingHttp;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

final class WithholdingAfterRateLimit extends ForwardingHttp {

    private final RateLimitTrip trip;
    private final BooleanSupplier withheld;

    private WithholdingAfterRateLimit(Http delegate, RateLimitTrip trip, BooleanSupplier withheld) {
        super(delegate);
        this.trip = trip;
        this.withheld = withheld;
    }

    static RateLimitedSends over(Http http, RateLimitTrip trip) {
        return new RateLimitedSends(new WithholdingAfterRateLimit(http, trip, trip::barsProbes),
                new WithholdingAfterRateLimit(http, trip, trip::barsConfirmations));
    }

    @Override
    protected HttpRequestResponse incoming(HttpRequestResponse exchange) {
        trip.record(exchange);
        return exchange;
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return unlessTripped(request, () -> super.sendRequest(request));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return unlessTripped(request, () -> super.sendRequest(request, httpMode));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return unlessTripped(request, () -> super.sendRequest(request, httpMode, connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return unlessTripped(request, () -> super.sendRequest(request, requestOptions));
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        return requests.stream().map(this::sendRequest).toList();
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        return requests.stream().map(request -> sendRequest(request, httpMode)).toList();
    }

    private HttpRequestResponse unlessTripped(HttpRequest request, Supplier<HttpRequestResponse> send) {
        return withheld.getAsBoolean() ? HttpRequestResponse.httpRequestResponse(request, null) : send.get();
    }
}
