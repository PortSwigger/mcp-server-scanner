package com.mcpscanner.checks;

import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

final class SelectedToolsFilter {

    private SelectedToolsFilter() {}

    static Set<String> selectedToolNames(Supplier<ScanInventory> selectedInventorySupplier) {
        ScanInventory inventory = selectedInventorySupplier.get();
        if (inventory == null) {
            return Set.of();
        }
        Set<String> names = new LinkedHashSet<>(inventory.tools().size());
        for (McpToolDefinition tool : inventory.tools()) {
            names.add(tool.name());
        }
        return names;
    }

    static List<DiscoveredTool> retainSelected(List<DiscoveredTool> discovered,
                                               Set<String> selectedToolNames) {
        List<DiscoveredTool> retained = new ArrayList<>(discovered.size());
        for (DiscoveredTool tool : discovered) {
            if (selectedToolNames.contains(tool.name())) {
                retained.add(tool);
            }
        }
        return retained;
    }
}
