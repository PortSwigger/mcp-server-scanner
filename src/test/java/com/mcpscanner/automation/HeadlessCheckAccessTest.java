package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRun;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.JsonSchemaDefaults;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HeadlessCheckAccessTest {

    private static final CheckAccessCommand COMMAND = new CheckAccessCommand("http://target/mcp",
            TransportType.STREAMABLE_HTTP, new CommandAuth("alice-token", Map.of()), null, CommandIdentities.NONE);
    private static final List<AccessRow> ROWS = List.of(mock(AccessRow.class), mock(AccessRow.class));

    private static final McpToolDefinition ADMIN_EFFECT = new McpToolDefinition("admin-effect", "",
            "{\"type\":\"object\",\"properties\":{\"sql\":{\"type\":\"string\"}}}");

    private final ItemSeeds itemSeeds = new ItemSeeds();
    private final McpClientManager clientManager = mock(McpClientManager.class);
    private final HeadlessConnection connection = new HeadlessConnection(clientManager, useBurp -> { },
            new IdentityHandover(new IdentityRegistry(new IdentityStore(InMemoryPersistedObject.configStore(),
                    McpEventLog.noop())), new WriteReplayConfirmations(), (item, expectation) -> { },
                    itemSeeds::seedWith),
            new CurrentAuthHolder(), mock(SignedInSessionSeed.class));
    private final CheckAccessProgress progress = new CheckAccessProgress();
    private final List<String> steps = new ArrayList<>();
    private final List<Runnable> queued = new ArrayList<>();
    private final AtomicReference<AccessRunListener> runListener = new AtomicReference<>();
    private Runnable mining = () -> steps.add("mine");
    private CheckAccessStart start = (rows, listener) -> {
        steps.add("check access " + rows.size() + " rows");
        runListener.set(listener);
        return Optional.of(new AccessRun());
    };

    @BeforeEach
    void connects() {
        when(clientManager.connect(any())).thenAnswer(connecting -> {
            steps.add("connect");
            return new ConnectResult(List.of(), List.of(), List.of(), List.of(), null);
        });
    }

    @Test
    void connectsBeforeAnsweringAndPreparesInTheBackground() {
        CheckAccessStatus launched = checkAccess().launch(COMMAND);

        assertThat(launched.status()).isEqualTo(CheckAccessPhase.DISCOVERING);
        assertThat(steps).containsExactly("connect");
        assertThat(queued).hasSize(1);
    }

    @Test
    void waitsForDiscoveryThenMinesEveryUserBeforeCheckingTheMatrixRows() {
        checkAccess().launch(COMMAND);
        runQueued();

        assertThat(steps).containsExactly("connect", "await listings", "mine", "check access 2 rows");
        assertThat(progress.status().orElseThrow().status()).isEqualTo(CheckAccessPhase.RUNNING);
        assertThat(progress.status().orElseThrow().total()).isEqualTo(2);
    }

    @Test
    void pinsASeededToolToTheCommandsItemSeedArguments() {
        ObjectNode params = McpObjectMapper.INSTANCE.createObjectNode().put("name", "admin-effect");
        ObjectNode arguments = params.putObject("arguments").put("sql", "INSERT INTO privileged_effect VALUES (1)");

        checkAccess().launch(new CheckAccessCommand(COMMAND.endpoint(), COMMAND.transport(), COMMAND.auth(), null,
                new CommandIdentities(null, null, null, null, List.of(new SeedCall("tools/call", params)))));

        ScanTarget.Tool pinned = (ScanTarget.Tool) itemSeeds.pinned(new ScanTarget.Tool(ADMIN_EFFECT));
        assertThat(JsonSchemaDefaults.defaultArguments(pinned.tool().inputSchema())).isEqualTo(arguments);
    }

    @Test
    void reportsTheRunsEndThroughItsListener() {
        checkAccess().launch(COMMAND);
        runQueued();

        runListener.get().finished(new AccessRunSummary(2, 2, 1, false));

        assertThat(progress.status().orElseThrow().status()).isEqualTo(CheckAccessPhase.FINISHED);
    }

    @Test
    void aMiningFailureFailsTheLaunchAndChecksNothing() {
        mining = () -> {
            throw new IllegalStateException("Mining stopped at HTTP 429 after 0 values");
        };

        checkAccess().launch(COMMAND);
        runQueued();

        CheckAccessStatus status = progress.status().orElseThrow();
        assertThat(status.status()).isEqualTo(CheckAccessPhase.FAILED);
        assertThat(status.reason()).contains("Mining stopped at HTTP 429");
        assertThat(steps).doesNotContain("check access 2 rows");
    }

    @Test
    void aRunThatDoesNotStartFailsTheLaunch() {
        start = (rows, listener) -> Optional.empty();

        checkAccess().launch(COMMAND);
        runQueued();

        assertThat(progress.status().orElseThrow().status()).isEqualTo(CheckAccessPhase.FAILED);
        assertThat(progress.status().orElseThrow().reason()).contains("Check access did not start");
    }

    @Test
    void refusesASecondLaunchWhileTheFirstIsActiveWithoutReconnecting() {
        HeadlessCheckAccess checkAccess = checkAccess();
        checkAccess.launch(COMMAND);

        assertThatThrownBy(() -> checkAccess.launch(COMMAND)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already running");
        verify(clientManager).connect(any());
    }

    @Test
    void aFailedConnectLeavesNoLaunchBehind() {
        when(clientManager.connect(any())).thenThrow(new IllegalStateException("Failed to establish session"));

        assertThatThrownBy(() -> checkAccess().launch(COMMAND)).hasMessageContaining("Failed to establish session");
        assertThat(progress.status()).isEmpty();
        assertThat(queued).isEmpty();
    }

    @Test
    void launchesAgainOnceTheLastRunEnded() {
        HeadlessCheckAccess checkAccess = checkAccess();
        checkAccess.launch(COMMAND);
        runQueued();
        runListener.get().finished(new AccessRunSummary(2, 2, 0, false));

        checkAccess.launch(COMMAND);

        assertThat(progress.status().orElseThrow().status()).isEqualTo(CheckAccessPhase.DISCOVERING);
    }

    private HeadlessCheckAccess checkAccess() {
        return new HeadlessCheckAccess(connection, new CheckAccessSteps(() -> steps.add("await listings"),
                () -> mining.run(), () -> ROWS, (rows, listener) -> start.start(rows, listener)), progress,
                queued::add);
    }

    private void runQueued() {
        List<Runnable> work = List.copyOf(queued);
        queued.clear();
        work.forEach(Runnable::run);
    }
}
