package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

abstract class ForwardingUpstreamExchanges implements UpstreamExchanges {

    private final UpstreamExchanges exchanges;

    ForwardingUpstreamExchanges(UpstreamExchanges exchanges) {
        this.exchanges = exchanges;
    }

    @Override
    public List<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied) {
        return exchanges.upstreamOf(proxied);
    }

    @Override
    public void keepResolved(HttpRequestResponse proxied, List<HttpRequestResponse> items) {
        exchanges.keepResolved(proxied, items);
    }

    @Override
    public ExchangeLease retaining() {
        return exchanges.retaining();
    }

    @Override
    public String issueUrl(String url) {
        return exchanges.issueUrl(url);
    }

    @Override
    public boolean onProxy(String url) {
        return exchanges.onProxy(url);
    }
}
