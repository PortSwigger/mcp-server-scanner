package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;
import java.util.List;
import java.util.Objects;

final class ModalDestructiveScanPrompt implements DestructiveScanPrompt {

    private final DialogOwner owner;

    ModalDestructiveScanPrompt(DialogOwner owner) {
        this.owner = Objects.requireNonNull(owner, "owner");
    }

    @Override
    public DestructiveScanConfirmation.Result ask(Component parent, List<McpToolDefinition> nonReadOnly,
                                                  int selectedCount, String invoker) {
        return askLines(parent, DestructiveScanConfirmation.scanLines(nonReadOnly, selectedCount, invoker));
    }

    @Override
    public DestructiveScanConfirmation.Result askLines(Component parent, DestructiveScanConfirmation.Lines lines) {
        return DestructiveScanConfirmation.promptLines(owner, parent, lines);
    }
}
