package com.mcpscanner.automation;

import com.mcpscanner.access.AccessItem;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.WriteReplayConfirmations;

import java.util.List;

public final class ConfirmedAccessRows {

    private final AccessMatrix matrix;
    private final WriteReplayConfirmations confirmations;

    public ConfirmedAccessRows(AccessMatrix matrix, WriteReplayConfirmations confirmations) {
        this.matrix = matrix;
        this.confirmations = confirmations;
    }

    public List<AccessRow> rows() {
        return matrix.snapshot().rows().stream().filter(row -> replayable(row.item())).toList();
    }

    private boolean replayable(AccessItem item) {
        return !item.writes() || confirmations.confirmed(item.key().name());
    }
}
