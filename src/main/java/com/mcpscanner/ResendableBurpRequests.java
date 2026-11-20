package com.mcpscanner;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.ResendableRequests;

import java.util.function.Predicate;

final class ResendableBurpRequests implements Predicate<HttpRequest> {

    private volatile ResendableRequests reads;

    void bindTo(ResendableRequests reads) {
        this.reads = reads;
    }

    @Override
    public boolean test(HttpRequest request) {
        ResendableRequests bound = reads;
        return bound != null && bound.resendable(request.method(), request.bodyToString());
    }
}
