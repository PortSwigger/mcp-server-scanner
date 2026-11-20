package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.mcpscanner.mcp.RateLimitStop;
import java.util.Optional;

public final class ProbeChannel {

    public enum Exhaustion { RATE_LIMITED, QUOTA_SPENT, BUDGET_SPENT }

    private final Http http;
    private final SendBudget budget;
    private boolean budgetRefusedAProbe;

    public ProbeChannel(Http http, int budget) {
        this.http = http;
        this.budget = new SendBudget(budget);
    }

    public HttpRequestResponse send(HttpRequest request) {
        HttpRequestResponse exchange = http.sendRequest(request);
        record(exchange);
        return exchange;
    }

    public void record(HttpRequestResponse sentElsewhere) {
        budget.record(RateLimitStop.of(sentElsewhere));
    }

    public boolean exhausted() {
        budgetRefusedAProbe |= budget.exhausted() && !budget.rateLimited();
        return budget.exhausted();
    }

    public boolean barsConfirmation() {
        return exhausted()
                && (budget.limitReached() || budget.answeredTooManyRequests());
    }

    public Optional<Exhaustion> exhaustion() {
        Optional<Exhaustion> rateLimit = budget.rateLimitStop().map(ProbeChannel::exhaustionOf);
        if (rateLimit.isPresent()) {
            return rateLimit;
        }
        return budgetRefusedAProbe ? Optional.of(Exhaustion.BUDGET_SPENT) : Optional.empty();
    }

    private static Exhaustion exhaustionOf(RateLimitStop stop) {
        return stop == RateLimitStop.QUOTA_SPENT ? Exhaustion.QUOTA_SPENT : Exhaustion.RATE_LIMITED;
    }

    public int budget() {
        return budget.limit();
    }

}
