package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;
import java.util.List;

public interface DestructiveScanPrompt {

    static DestructiveScanPrompt modal(DialogOwner owner) {
        return new ModalDestructiveScanPrompt(owner);
    }

    DestructiveScanConfirmation.Result ask(Component parent, List<McpToolDefinition> nonReadOnly, int selectedCount,
                                           String invoker);

    DestructiveScanConfirmation.Result askLines(Component parent, DestructiveScanConfirmation.Lines lines);
}
