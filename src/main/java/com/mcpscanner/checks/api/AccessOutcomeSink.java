package com.mcpscanner.checks.api;

public interface AccessOutcomeSink {

    void record(AccessItemKey item, String principalId, AccessOutcome outcome);

    void recordAnonymous(AccessItemKey item, AccessOutcome outcome);

    default void recordFinding(AccessItemKey item, String principalId, AccessFinding finding) {
    }

    default void recordNotCompared(AccessItemKey item, String reason) {
    }
}
