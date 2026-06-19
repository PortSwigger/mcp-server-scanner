package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SelectedToolsFilterTest {

    private static DiscoveredTool discovered(String name) {
        return new DiscoveredTool(name, JsonNodeFactory.instance.objectNode());
    }

    private static McpToolDefinition definition(String name) {
        return new McpToolDefinition(name, "", "{}");
    }

    @Test
    void extractsToolNamesPreservingOrder() {
        ScanInventory inventory = ScanInventory.toolsOnly(
                List.of(definition("alpha"), definition("beta")));

        Set<String> names = SelectedToolsFilter.selectedToolNames(() -> inventory);

        assertThat(names).containsExactly("alpha", "beta");
    }

    @Test
    void returnsEmptySetForNullInventory() {
        assertThat(SelectedToolsFilter.selectedToolNames(() -> null)).isEmpty();
    }

    @Test
    void returnsEmptySetForEmptyInventory() {
        assertThat(SelectedToolsFilter.selectedToolNames(ScanInventory::empty)).isEmpty();
    }

    @Test
    void retainSelectedKeepsOnlyDiscoveredToolsMatchingSelection() {
        List<DiscoveredTool> discovered = List.of(
                discovered("alpha"), discovered("beta"), discovered("gamma"));

        List<DiscoveredTool> retained =
                SelectedToolsFilter.retainSelected(discovered, Set.of("alpha", "gamma"));

        assertThat(retained).extracting(DiscoveredTool::name).containsExactly("alpha", "gamma");
    }

    @Test
    void retainSelectedReturnsEmptyWhenNothingMatches() {
        List<DiscoveredTool> discovered = List.of(discovered("alpha"));

        assertThat(SelectedToolsFilter.retainSelected(discovered, Set.of("missing"))).isEmpty();
    }
}
