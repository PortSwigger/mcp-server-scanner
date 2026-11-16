package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;
import java.util.function.UnaryOperator;

@FunctionalInterface
public interface UpstreamExchanges {

    UpstreamExchanges NONE = proxied -> Optional.empty();

    Optional<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied);

    default ExchangeLease retaining() {
        return ExchangeLease.NONE;
    }

    default String issueUrl(String url) {
        return url;
    }

    default UpstreamExchanges filingIssuesUnder(UnaryOperator<String> stableUrls) {
        UpstreamExchanges exchanges = this;
        return new UpstreamExchanges() {
            @Override
            public Optional<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied) {
                return exchanges.upstreamOf(proxied);
            }

            @Override
            public ExchangeLease retaining() {
                return exchanges.retaining();
            }

            @Override
            public String issueUrl(String url) {
                return stableUrls.apply(exchanges.issueUrl(url));
            }
        };
    }
}
