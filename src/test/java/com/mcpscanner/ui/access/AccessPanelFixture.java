package com.mcpscanner.ui.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.RecordingComparison;
import com.mcpscanner.access.RecordingHttp;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.ui.sendto.SendToDestination;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

final class AccessPanelFixture implements AutoCloseable {

    final AccessFixtures fixtures;
    final RecordingComparison check = new RecordingComparison();
    final RecordingHttp http = new RecordingHttp();
    final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    final List<List<McpToolDefinition>> approvals = new CopyOnWriteArrayList<>();
    final List<String> repeaterTitles = new CopyOnWriteArrayList<>();
    final List<HttpRequest> repeaterRequests = new CopyOnWriteArrayList<>();
    final AtomicInteger refreshes = new AtomicInteger();
    final AtomicInteger panelRefreshes = new AtomicInteger();
    final AccessMatrix matrix;
    final OwnerRequests requests;
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
    private int otherUserCount = 1;
    private AccessPanel panel;

    AccessPanelFixture(AccessFixtures fixtures) {
        this.fixtures = fixtures;
        this.matrix = fixtures.matrix();
        this.requests = new OwnerRequests(AccessPanelFixture::primaryRequest, new IdentityRequests(fixtures::roster));
    }

    AccessPanelFixture otherUserCount(int count) {
        otherUserCount = count;
        return this;
    }

    AccessPanel panel() throws Exception {
        if (panel == null) {
            panel = onEdt(() -> new AccessPanel(services(), tools -> approvals.add(tools), this::repeater,
                    message -> { }));
        }
        return panel;
    }

    AccessServices services() {
        CheckAccessRunner runner = new CheckAccessRunner(check, http, requests, issue -> { },
                new WriteReplays(confirmations, new MatrixAccessLedger(matrix, confirmations)), runs,
                McpEventLog.noop());
        return new AccessServices(matrix, runner, requests, confirmations, refreshes::incrementAndGet,
                () -> {
                    panelRefreshes.incrementAndGet();
                    return otherUserCount;
                });
    }

    Optional<SendToDestination> repeater() {
        return Optional.of(SendToDestination.of("Repeater", (request, title) -> {
            repeaterRequests.add(request);
            repeaterTitles.add(title);
        }));
    }

    static HttpRequest primaryRequest(ScanTarget target) {
        return ImmutableHttpRequest.post("https://mcp.test/mcp", Map.of("Authorization", "Bearer alice-token",
                McpHeaders.SESSION_ID, "primary-session"), "{\"call\":\"" + target.identifier() + "\"}");
    }

    static <T> T onEdt(Callable<T> callable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return callable.call();
        }
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(callable.call());
            } catch (Exception exception) {
                failure.set(exception);
            }
        });
        if (failure.get() != null) {
            throw failure.get();
        }
        return result.get();
    }

    interface EdtAction {
        void run() throws Exception;
    }

    static void run(EdtAction runnable) throws Exception {
        onEdt(() -> {
            runnable.run();
            return null;
        });
    }

    @Override
    public void close() {
        runs.shutdown();
    }
}
