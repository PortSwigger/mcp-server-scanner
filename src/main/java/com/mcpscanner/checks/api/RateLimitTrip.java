package com.mcpscanner.checks.api;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.mcp.RateLimitStop;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

final class RateLimitTrip {

    private final AtomicBoolean quotaSpent = new AtomicBoolean();
    private final AtomicBoolean tooManyRequests = new AtomicBoolean();

    void record(HttpRequestResponse exchange) {
        RateLimitStop.of(exchange).ifPresent(stop -> (stop == RateLimitStop.TOO_MANY_REQUESTS
                ? tooManyRequests : quotaSpent).set(true));
    }

    boolean barsProbes() {
        return quotaSpent.get() || barsConfirmations();
    }

    boolean barsConfirmations() {
        return tooManyRequests.get();
    }

    Optional<SkipReason> reason() {
        if (tooManyRequests.get()) {
            return Optional.of(SkipReason.rateLimited());
        }
        return quotaSpent.get() ? Optional.of(SkipReason.quotaSpent()) : Optional.empty();
    }
}
