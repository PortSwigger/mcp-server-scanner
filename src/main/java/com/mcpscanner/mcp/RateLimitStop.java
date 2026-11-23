package com.mcpscanner.mcp;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

public enum RateLimitStop {
    TOO_MANY_REQUESTS,
    QUOTA_SPENT;

    public static Optional<RateLimitStop> of(HttpRequestResponse exchange) {
        if (TooManyRequests.answered(exchange)) {
            return Optional.of(TOO_MANY_REQUESTS);
        }
        return exchange != null && RateLimitQuota.spent(exchange.response()) ? Optional.of(QUOTA_SPENT)
                : Optional.empty();
    }
}
