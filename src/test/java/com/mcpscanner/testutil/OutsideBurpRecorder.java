package com.mcpscanner.testutil;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.ForwardingHttp;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class OutsideBurpRecorder extends ForwardingHttp {

    private final List<HttpRequestResponse> reported = new CopyOnWriteArrayList<>();
    private final java.util.concurrent.atomic.AtomicInteger refusals = new java.util.concurrent.atomic.AtomicInteger();

    public OutsideBurpRecorder(Http delegate) {
        super(delegate);
    }

    public List<HttpRequestResponse> reported() {
        return List.copyOf(reported);
    }

    public int refusals() {
        return refusals.get();
    }

    @Override
    public void streamRefused() {
        refusals.incrementAndGet();
        super.streamRefused();
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    @Override
    public void sentOutsideBurp(HttpRequestResponse exchange) {
        reported.add(exchange);
        super.sentOutsideBurp(exchange);
    }
}
