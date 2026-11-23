package com.mcpscanner.checks.api;

import com.mcpscanner.checks.shared.probe.ProbeChannel;

import java.util.Optional;

public final class ProbeStops {

    private final CheckLog log;
    private final ProbeChannel channel;
    private final String subject;

    public ProbeStops(CheckLog log, ProbeChannel channel, String subject) {
        this.log = log;
        this.channel = channel;
        this.subject = subject;
    }

    public void notRun(SkipReason unlessExhausted) {
        log.notRun(subject, exhaustion().orElse(unlessExhausted));
    }

    public boolean notRunIfExhausted() {
        return channel.exhausted() && reportedExhaustion();
    }

    public boolean notRunIfConfirmationBarred() {
        return channel.barsConfirmation() && reportedExhaustion();
    }

    public boolean reportedExhaustion() {
        Optional<SkipReason> exhaustion = exhaustion();
        exhaustion.ifPresent(reason -> log.notRun(subject, reason));
        return exhaustion.isPresent();
    }

    private Optional<SkipReason> exhaustion() {
        return channel.exhaustion().map(this::reasonFor);
    }

    private SkipReason reasonFor(ProbeChannel.Exhaustion exhaustion) {
        return switch (exhaustion) {
            case RATE_LIMITED -> SkipReason.rateLimited();
            case QUOTA_SPENT -> SkipReason.quotaSpent();
            case BUDGET_SPENT -> SkipReason.budgetExhausted(channel.budget() + " probe requests");
        };
    }
}
