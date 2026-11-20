package com.mcpscanner.checks.shared.probe;

import com.mcpscanner.mcp.RateLimitStop;

import java.util.Optional;

public final class SendBudget {

    private final int limit;
    private int sent;
    private boolean quotaSpent;
    private boolean tooManyRequests;

    public SendBudget(int limit) {
        this.limit = limit;
    }

    public void record(Optional<RateLimitStop> stop) {
        sent++;
        stop.ifPresent(this::note);
    }

    public boolean affords(int sends) {
        return !rateLimited() && sent + sends <= limit;
    }

    public boolean limitReached() {
        return sent >= limit;
    }

    public boolean exhausted() {
        return !affords(1);
    }

    private void note(RateLimitStop stop) {
        tooManyRequests |= stop == RateLimitStop.TOO_MANY_REQUESTS;
        quotaSpent |= stop == RateLimitStop.QUOTA_SPENT;
    }

    public boolean rateLimited() {
        return tooManyRequests || quotaSpent;
    }

    public boolean answeredTooManyRequests() {
        return tooManyRequests;
    }

    public Optional<RateLimitStop> rateLimitStop() {
        if (tooManyRequests) {
            return Optional.of(RateLimitStop.TOO_MANY_REQUESTS);
        }
        return quotaSpent ? Optional.of(RateLimitStop.QUOTA_SPENT) : Optional.empty();
    }

    public int limit() {
        return limit;
    }

    public int sent() {
        return sent;
    }
}
