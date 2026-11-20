package com.mcpscanner.automation;

import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.PersistedAccessExpectations;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.identity.discovery.IdentityListing;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ConfirmedAccessRowsTest {

    private static final McpToolDefinition SEARCH = AccessFixtures.readOnlyTool("search");
    private static final McpToolDefinition DELETE_DOCUMENT = new McpToolDefinition("delete_document", "", "{}");
    private static final McpToolDefinition CREATE_LIST = new McpToolDefinition("create_list", "", "{}");
    private static final McpResourceDefinition NOTES = new McpResourceDefinition("notes://a", "notes", "", null);

    private final IdentityRegistry registry = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final AccessMatrix matrix = new AccessMatrix(new IdentityRosterSource(NoAuthStrategy::new, registry),
            () -> Map.of(Principal.PRIMARY_ID, new DiscoveryOutcome.Listed(IdentityListing.of(new ConnectResult(
                    List.of(SEARCH, DELETE_DOCUMENT, CREATE_LIST), List.of(NOTES), List.of(), List.of(), null)))),
            new PersistedAccessExpectations(InMemoryPersistedObject.configStore(), () -> "http://target/mcp"),
            new SyntheticPrincipals(NoAuthStrategy::new).all());

    @Test
    void keepsEveryReadAndOnlyTheWritesTheCommandConfirmed() {
        confirmations.confirm(List.of(CREATE_LIST));

        List<AccessRow> rows = new ConfirmedAccessRows(matrix, confirmations).rows();

        assertThat(rows).extracting(row -> row.item().key().name())
                .containsExactlyInAnyOrder("search", "create_list", "notes://a");
    }
}
