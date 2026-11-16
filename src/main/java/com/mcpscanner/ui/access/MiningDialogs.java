package com.mcpscanner.ui.access;

import com.mcpscanner.identity.EnteredValue;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface MiningDialogs {

    static MiningDialogs modal(DialogOwner owner) {
        return new ModalMiningDialogs(owner);
    }

    MineFirstChoice mineFirst(Component parent, ToolsToCall tools);

    boolean confirmMining(Component parent, ToolsToCall tools);

    ClearChoice clearMined(Component parent, String userName);

    Optional<EnteredValue> enterValue(Component parent, Optional<EnteredValue> current);

    Optional<Set<String>> chooseWriteTools(Component parent, List<McpToolDefinition> tools, Set<String> selected);
}
