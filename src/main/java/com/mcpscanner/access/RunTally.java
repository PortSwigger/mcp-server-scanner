package com.mcpscanner.access;

import java.util.Optional;

final class RunTally {

    private final int total;
    private final AccessRunListener listener;
    private int checked;
    private int issues;
    private Optional<String> stopReason = Optional.empty();

    RunTally(int total, AccessRunListener listener) {
        this.total = total;
        this.listener = listener;
    }

    void completed(RowOutcome outcome, Optional<String> stop) {
        issues += outcome.issues();
        if (stopReason.isEmpty()) {
            stopReason = stop;
        }
        listener.progress(++checked, total);
    }

    void raised(int runIssues) {
        issues += runIssues;
    }

    boolean stopped() {
        return stopReason.isPresent();
    }

    Optional<String> stopReason() {
        return stopReason;
    }

    AccessRunSummary summary(boolean cancelled) {
        return new AccessRunSummary(checked, total, issues, cancelled, stopReason);
    }
}
