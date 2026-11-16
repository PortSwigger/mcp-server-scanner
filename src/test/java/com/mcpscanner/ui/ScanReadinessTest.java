package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ScanReadinessTest {

    private static final ScanInventory TWO_TOOLS_ONE_RESOURCE = new ScanInventory(
            List.of(new McpToolDefinition("a", "", "{}"), new McpToolDefinition("b", "", "{}")),
            List.of(new McpResourceDefinition("docs://x", "x", "", "text/plain")), List.of(), List.of());

    @Test
    void disconnectedScanExplainsThatItNeedsAConnection() {
        ScanReadiness readiness = new ScanReadiness(false, TWO_TOOLS_ONE_RESOURCE, requests(5));

        assertThat(readiness.blocker()).contains("Connect to an MCP server first");
        assertThat(readiness.tooltip(ScanMode.MCP_ONLY)).isEqualTo("Connect to an MCP server first");
    }

    @Test
    void connectedScanThatWouldSendNothingAsksForAnItemOrARequestFamily() {
        ScanReadiness readiness = new ScanReadiness(true, ScanInventory.empty(), requests(0));

        assertThat(readiness.blocker())
                .contains("Tick a tool, resource, template or prompt, or turn on a request family under Requests");
        assertThat(readiness.shortBlocker()).contains("Tick items to scan");
        assertThat(readiness.buttonLabel()).isEqualTo("Scan");
    }

    @ParameterizedTest
    @EnumSource(ScanMode.class)
    void connectedScanWithNothingTickedNamesTheProtocolRequestsItSends(ScanMode mode) {
        ScanReadiness readiness = new ScanReadiness(true, ScanInventory.empty(),
                requests("initialize", "ping", "tools/list"));

        assertThat(readiness.blocker()).isEmpty();
        assertThat(readiness.shortBlocker()).isEmpty();
        assertThat(readiness.buttonLabel()).isEqualTo("Scan 3 protocol requests");
        assertThat(readiness.summary()).isEqualTo("3 protocol requests");
        assertThat(readiness.tooltip(mode)).isEqualTo("Send 3 protocol requests with " + ScanModeText.of(mode).label()
                + ": initialize, ping, tools/list. No items are ticked, so no tool, resource or prompt is called."
                + " Choose these under Requests.");
    }

    @Test
    void repeatedProtocolRequestsAreNamedOnce() {
        ScanReadiness readiness = new ScanReadiness(true, ScanInventory.empty(),
                requests("resources/subscribe", "resources/subscribe"));

        assertThat(readiness.tooltip(ScanMode.MCP_ONLY)).contains(": resources/subscribe. ");
    }

    @Test
    void tickedItemsThatWouldSendNothingAreBlocked() {
        ScanReadiness readiness = new ScanReadiness(true, TWO_TOOLS_ONE_RESOURCE, requests(0));

        assertThat(readiness.blocker()).isPresent();
        assertThat(readiness.buttonLabel()).isEqualTo("Scan");
    }

    @ParameterizedTest
    @EnumSource(ScanMode.class)
    void readyScanNamesWhatWillBeScannedAndTheMode(ScanMode mode) {
        ScanReadiness readiness = new ScanReadiness(true, TWO_TOOLS_ONE_RESOURCE, requests(5));

        assertThat(readiness.blocker()).isEmpty();
        assertThat(readiness.buttonLabel()).isEqualTo("Scan 3 items");
        assertThat(readiness.summary()).isEqualTo("3 items (2 tools, 1 resource)");
        assertThat(readiness.tooltip(mode))
                .isEqualTo("Scan the 3 selected items (2 tools, 1 resource) with " + ScanModeText.of(mode).label());
    }

    @Test
    void summaryUsesSingularAndSkipsEmptyKinds() {
        ScanInventory onePrompt = new ScanInventory(List.of(), List.of(), List.of(),
                List.of(new McpPromptDefinition("p", "", List.of())));

        assertThat(ScanReadiness.describe(onePrompt)).isEqualTo("1 item (1 prompt)");
    }

    @Test
    void connectedScanWhoseRequestsAreStillBeingCountedWaits() {
        ScanReadiness readiness = new ScanReadiness(true, ScanInventory.empty(), Optional.empty());

        assertThat(readiness.blocker()).contains("Counting requests…");
        assertThat(readiness.tooltip(ScanMode.MCP_ONLY)).isEqualTo("Counting requests…");
        assertThat(readiness.shortBlocker()).isEmpty();
        assertThat(readiness.buttonLabel()).isEqualTo("Scan");
    }

    @Test
    void tickedItemsStillBeingCountedKeepTheItemLabel() {
        ScanReadiness readiness = new ScanReadiness(true, TWO_TOOLS_ONE_RESOURCE, Optional.empty());

        assertThat(readiness.blocker()).contains("Counting requests…");
        assertThat(readiness.buttonLabel()).isEqualTo("Scan 3 items");
    }

    @Test
    void disconnectedScanAsksForAConnectionEvenBeforeAnyCount() {
        ScanReadiness readiness = new ScanReadiness(false, TWO_TOOLS_ONE_RESOURCE, Optional.empty());

        assertThat(readiness.blocker()).contains("Connect to an MCP server first");
    }

    private static PlannedRequests requests(String... subjects) {
        return new PlannedRequests(List.of(subjects));
    }

    private static PlannedRequests requests(int count) {
        return new PlannedRequests(Collections.nCopies(count, "tools/call"));
    }
}
