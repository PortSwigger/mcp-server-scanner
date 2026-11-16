package com.mcpscanner.ui.access;

import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.ToolGate;
import com.mcpscanner.mcp.McpToolDefinition;

import java.awt.Component;
import java.util.List;
import java.util.Optional;
import java.util.Set;

final class MiningConsent {

    private final AccessMining mining;
    private final MiningDialogs dialogs;
    private Optional<Consent> given = Optional.empty();

    MiningConsent(AccessMining mining, MiningDialogs dialogs) {
        this.mining = mining;
        this.dialogs = dialogs;
    }

    boolean confirmMining(Component parent) {
        ToolsToCall tools = toolsToCall();
        if (needsConsent(tools) && !dialogs.confirmMining(parent, tools)) {
            return false;
        }
        record(tools);
        return true;
    }

    MineFirstChoice mineFirst(Component parent) {
        ToolsToCall tools = toolsToCall();
        MineFirstChoice choice = dialogs.mineFirst(parent, tools);
        if (choice == MineFirstChoice.MINE) {
            record(tools);
        }
        return choice;
    }

    ToolsToCall toolsToCall() {
        List<McpToolDefinition> tools = mining.tools();
        ToolGate gate = new ToolGate(mining.preferences().settings(tools).allowedTools());
        return ToolsToCall.of(tools.stream().filter(gate::mayCall).toList());
    }

    private boolean needsConsent(ToolsToCall tools) {
        return tools.writes() && given.filter(consent -> consent.covers(mining.connection(), tools)).isEmpty();
    }

    private void record(ToolsToCall tools) {
        given = Optional.of(new Consent(mining.connection(), Set.copyOf(tools.mayWrite())));
    }

    private record Consent(long connection, Set<String> writeTools) {

        boolean covers(long current, ToolsToCall tools) {
            return connection == current && writeTools.containsAll(tools.mayWrite());
        }
    }
}
