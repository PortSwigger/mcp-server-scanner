package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.ForwardingHttp;

import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

final class InFlightLimit extends ForwardingHttp {

    static final int MOST_IN_FLIGHT = 8;
    private static final String CANCELLED = "Check access was cancelled while waiting to send";

    private final Semaphore slots;

    InFlightLimit(Http delegate) {
        this(delegate, new Semaphore(MOST_IN_FLIGHT));
    }

    InFlightLimit(Http delegate, Semaphore slots) {
        super(delegate);
        this.slots = slots;
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return inSlot(() -> super.sendRequest(request));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return inSlot(() -> super.sendRequest(request, httpMode));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return inSlot(() -> super.sendRequest(request, httpMode, connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return inSlot(() -> super.sendRequest(request, requestOptions));
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        return requests.stream().map(this::sendRequest).toList();
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        return requests.stream().map(request -> sendRequest(request, httpMode)).toList();
    }

    private HttpRequestResponse inSlot(Supplier<HttpRequestResponse> send) {
        acquire();
        try {
            return send.get();
        } finally {
            slots.release();
        }
    }

    private void acquire() {
        try {
            slots.acquire();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AccessRunStopped(CANCELLED);
        }
    }
}
