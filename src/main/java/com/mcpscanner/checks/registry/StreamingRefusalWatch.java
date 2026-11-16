package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.ForwardingHttp;
import com.mcpscanner.mcp.BurpStreamingRefusal;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

final class StreamingRefusalWatch extends ForwardingHttp {

    private final AtomicBoolean refused = new AtomicBoolean();

    StreamingRefusalWatch(Http delegate) {
        super(delegate);
    }

    boolean sawRefusal() {
        return refused.get();
    }

    @Override
    public void streamRefused() {
        refused.set(true);
        super.streamRefused();
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return watching(() -> super.sendRequest(request));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return watching(() -> super.sendRequest(request, httpMode));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return watching(() -> super.sendRequest(request, httpMode, connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return watching(() -> super.sendRequest(request, requestOptions));
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    private HttpRequestResponse watching(Supplier<HttpRequestResponse> send) {
        try {
            return send.get();
        } catch (RuntimeException failure) {
            if (BurpStreamingRefusal.refused(failure)) {
                refused.set(true);
            }
            throw failure;
        }
    }
}
