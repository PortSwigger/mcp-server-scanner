package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;

public final class RetainingHttp extends ForwardingHttp {

    private final ExchangeLease lease;

    public RetainingHttp(Http delegate, ExchangeLease lease) {
        super(delegate);
        this.lease = Objects.requireNonNull(lease);
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    @Override
    protected HttpRequestResponse incoming(HttpRequestResponse exchange) {
        lease.hold(exchange);
        return exchange;
    }
}
