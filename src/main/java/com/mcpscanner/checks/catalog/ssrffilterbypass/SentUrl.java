package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

record SentUrl(ProbeUrl probe, HttpRequestResponse exchange) {

    String url() {
        return probe.url();
    }

    boolean answered() {
        return exchange != null && exchange.response() != null;
    }

    Optional<String> signature() {
        return Optional.of(this).filter(SentUrl::answered)
                .map(sent -> ReplySignature.of(exchange.response(), probe));
    }

    SentUrl kept(HttpRequestResponse keptExchange) {
        return new SentUrl(probe, keptExchange);
    }
}
