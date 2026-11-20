package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

@FunctionalInterface
public interface UpstreamExchanges {

    UpstreamExchanges NONE = proxied -> List.of();

    List<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied);

    default void keepResolved(HttpRequestResponse proxied, List<HttpRequestResponse> items) {
    }

    default ExchangeLease retaining() {
        return ExchangeLease.NONE;
    }

    default String issueUrl(String url) {
        return url;
    }

    default boolean onProxy(String url) {
        return false;
    }

    default UpstreamExchanges filingIssuesUnder(UnaryOperator<String> stableUrls) {
        return new ForwardingUpstreamExchanges(this) {
            @Override
            public String issueUrl(String url) {
                return stableUrls.apply(super.issueUrl(url));
            }
        };
    }

    default UpstreamExchanges proxiedThrough(Supplier<HttpService> proxy) {
        return new ForwardingUpstreamExchanges(this) {
            @Override
            public boolean onProxy(String url) {
                return Origin.of(url).equals(Optional.of(Origin.of(proxy.get())));
            }
        };
    }
}
