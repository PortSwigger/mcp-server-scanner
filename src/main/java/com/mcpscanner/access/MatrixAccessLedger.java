package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.AccessOutcome;

public final class MatrixAccessLedger implements AccessLedger {

    private final AccessMatrix matrix;
    private final WriteReplayConfirmations confirmations;

    public MatrixAccessLedger(AccessMatrix matrix, WriteReplayConfirmations confirmations) {
        this.matrix = matrix;
        this.confirmations = confirmations;
    }

    @Override
    public AccessExpectation expectationFor(AccessItemKey item) {
        return matrix.expectationFor(item);
    }

    @Override
    public void record(AccessItemKey item, String principalId, AccessOutcome outcome) {
        matrix.record(item, principalId, outcome);
    }

    @Override
    public void recordAnonymous(AccessItemKey item, AccessOutcome outcome) {
        matrix.recordAnonymous(item, outcome);
    }

    @Override
    public void recordFinding(AccessItemKey item, String principalId, AccessFinding finding) {
        matrix.recordFinding(item, principalId, finding);
    }

    @Override
    public void recordNotCompared(AccessItemKey item, String reason) {
        matrix.recordNotCompared(item, reason);
    }

    @Override
    public boolean permitsReplay(AccessItemKey item) {
        return item.kind() == AccessItemKey.Kind.RESOURCE || knownRead(item) || confirmations.confirmed(item.name());
    }

    @Override
    public boolean replaysWrite(AccessItemKey item) {
        return item.kind() == AccessItemKey.Kind.TOOL && !knownRead(item) && confirmations.confirmed(item.name());
    }

    private boolean knownRead(AccessItemKey item) {
        return matrix.row(item).filter(row -> !row.item().writes()).isPresent();
    }
}
