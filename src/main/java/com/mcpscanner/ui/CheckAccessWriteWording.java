package com.mcpscanner.ui;

import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.MinedArguments;

import java.awt.Component;
import java.util.List;

final class CheckAccessWriteWording implements WriteToolWording {

    private static final String REPLAY = "Check access will replay the owner's own calls to these tools as every "
            + "compared user, " + SyntheticLabel.ALWAYS_COMPARED;
    private static final String EFFECT = "Each replay repeats the call's effect: it can modify, create, or delete "
            + "data on the target — irreversible.";

    @Override
    public DestructiveScanConfirmation.Result ask(DestructiveScanPrompt prompt, Component parent,
                                                  List<McpToolDefinition> writes, int selectedCount) {
        return prompt.askLines(parent, new DestructiveScanConfirmation.Lines(REPLAY + ". " + EFFECT,
                DestructiveScanPolicy.countLine(writes.size(), selectedCount),
                writes.stream().map(DestructiveScanPolicy::formatToolLine).toList(),
                DestructiveScanConfirmation.Purpose.CHECK_ACCESS));
    }

    @Override
    public DestructiveScanConfirmation.Lines minedLines(List<McpToolDefinition> writes, int selectedCount,
                                                        MinedArguments mined) {
        return MinedWriteLines.of(writes, selectedCount, REPLAY + ", with the argument values below. "
                        + MinedWriteLines.MINED_VALUES + " " + EFFECT,
                DestructiveScanConfirmation.Purpose.CHECK_ACCESS_WITH_MINED_VALUES, mined);
    }
}
