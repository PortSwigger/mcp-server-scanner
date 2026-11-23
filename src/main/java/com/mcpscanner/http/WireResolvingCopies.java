package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

public final class WireResolvingCopies implements TempFileCopies {

    private final TempFileCopies copies;
    private final UpstreamExchanges exchanges;
    private final UpstreamEvidence upstreamEvidence;

    public WireResolvingCopies(TempFileCopies copies, UpstreamExchanges exchanges) {
        this.copies = Objects.requireNonNull(copies, "copies");
        this.exchanges = Objects.requireNonNull(exchanges, "exchanges");
        this.upstreamEvidence = new UpstreamEvidence(exchanges);
    }

    @Override
    public HttpRequestResponse kept(HttpRequestResponse exchange) {
        List<HttpRequestResponse> resolved = upstreamEvidence.resolved(exchange);
        if (resolved.size() == 1) {
            return copies.kept(resolved.get(0));
        }
        exchanges.keepResolved(exchange, resolved.stream().map(copies::kept).toList());
        return copies.kept(exchange);
    }
}
