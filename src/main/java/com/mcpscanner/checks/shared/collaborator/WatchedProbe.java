package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorPayload;
import com.mcpscanner.checks.shared.scancontext.CurrentInvocation;
import com.mcpscanner.checks.shared.scancontext.CurrentScan;
import com.mcpscanner.checks.shared.scancontext.ScanContext;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

final class WatchedProbe {

    private final List<CollaboratorPayload> payloads;
    private final InteractionListener listener;
    private final Optional<ScanContext> sentBy;
    private final Instant settlesAt;
    private final Instant expiresAt;
    private final CurrentInvocation.Retention retention;
    private int delivered;
    private boolean settled;

    WatchedProbe(Collection<CollaboratorPayload> payloads, InteractionListener listener,
                 Optional<ScanContext> sentBy, Instant settlesAt, Instant expiresAt,
                 CurrentInvocation.Retention retention) {
        this.payloads = List.copyOf(payloads);
        this.listener = listener;
        this.sentBy = sentBy;
        this.settlesAt = settlesAt;
        this.expiresAt = expiresAt;
        this.retention = retention;
    }

    List<CollaboratorPayload> payloads() {
        return payloads;
    }

    boolean hasNews(ObservedInteractions soFar) {
        return soFar.inArrivalOrder().size() > delivered;
    }

    boolean sentByScan(long scanId) {
        return sentBy.filter(context -> context.scanId() == scanId).isPresent();
    }

    WatchDecision deliver(ObservedInteractions soFar) {
        delivered = soFar.inArrivalOrder().size();
        return CurrentScan.within(sentBy, () -> listener.interacted(soFar));
    }

    void settleIfPolledAfterWindow(Instant polledAt) {
        settled = settled || !polledAt.isBefore(settlesAt);
    }

    boolean settled() {
        return settled;
    }

    void release() {
        retention.release();
    }

    boolean expiredAt(Instant now) {
        return now.isAfter(expiresAt);
    }
}
