package com.mcpscanner.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.comparison.CrossIdentityPorts;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.AccessFixtures.tool;
import static com.mcpscanner.access.AccessFixtures.toolKey;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static org.assertj.core.api.Assertions.assertThat;

class SyntheticCheckAccessTest {

    private final AccessFixtures fixtures = new AccessFixtures();
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
    private final SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> new BearerTokenAuthStrategy("alice-token"));
    private final SyntheticCallLog calls = new SyntheticCallLog();
    private final FakeMcpTarget target = new FakeMcpTarget(request -> principal(request) == null
            ? FakeReply.unauthorized() : FakeReply.result("users: alice, bob"));
    private AccessMatrix matrix;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void stopRuns() {
        runs.shutdown();
    }

    @Test
    void withOnlyThePrimaryConfiguredEachItemIsCalledWithoutACredentialAndWithTheFakeToken() {
        checkAccess(List.of(readOnlyTool("list_users")), tools -> true);

        List<String> principals = target.sent().stream().map(FakeMcpTarget::principal).toList();
        assertThat(principals.get(0)).isEqualTo("alice-token");
        assertThat(principals.subList(1, principals.size())).containsExactlyInAnyOrder(null, fakeToken());
        AccessRow row = matrix.row(toolKey("list_users")).orElseThrow();
        assertThat(row.anonymous().outcome()).contains(AccessOutcome.REFUSED);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).outcome()).contains(AccessOutcome.SAME_RESULT);
        assertThat(calls.call(toolKey("list_users"), Principal.FAKE_TOKEN_ID)).isPresent();
    }

    @Test
    void aDeclinedWriteToolGetsNoSyntheticCall() {
        Optional<AccessRun> run = checkAccess(List.of(tool("delete_user")), tools -> false);

        assertThat(run).isEmpty();
        assertThat(target.sent()).isEmpty();
    }

    @Test
    void aConfirmedWriteToolIsAlsoCalledWithoutACredentialAndWithTheFakeToken() {
        checkAccess(List.of(tool("delete_user")), tools -> true);

        assertThat(target.sent()).hasSize(3);
    }

    private Optional<AccessRun> checkAccess(List<McpToolDefinition> tools, WriteReplayApproval approval) {
        matrix = fixtures.lists(ALICE, tools, List.of()).matrix();
        List<AccessRow> rows = matrix.snapshot().rows();
        MatrixAccessLedger ledger = new MatrixAccessLedger(matrix, confirmations);
        AccessComparison comparison = new CrossIdentityComparison(McpEventLog.noop(),
                () -> new BearerTokenAuthStrategy("alice-token"), fixtures::roster,
                CrossIdentityPorts.of(ledger, PrincipalListings.unknown()), synthetic::all, calls);
        OwnerRequests requests = new OwnerRequests(SyntheticCheckAccessTest::ownerRequest,
                new IdentityRequests(fixtures::roster));
        CompletableFuture<AccessRunSummary> finished = new CompletableFuture<>();
        Optional<AccessRun> run = new CheckAccessRunner(comparison, target.http(), requests, issue -> { },
                new WriteReplays(confirmations, ledger), runs, McpEventLog.noop())
                .start(rows, approval, new AccessRunListener() {
                    @Override
                    public void progress(int done, int total) {
                    }

                    @Override
                    public void finished(AccessRunSummary summary) {
                        finished.complete(summary);
                    }
                });
        run.ifPresent(started -> valueWithin(Duration.ofSeconds(10), finished));
        return run;
    }

    private String fakeToken() {
        return synthetic.fakeToken().credentialHeaders().get().get("Authorization").replace("Bearer ", "");
    }

    private static HttpRequest ownerRequest(ScanTarget target) {
        return ImmutableHttpRequest.post("https://mcp.test/mcp",
                Map.of("Authorization", "Bearer alice-token", "Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\""
                        + target.identifier() + "\",\"arguments\":{}}}");
    }
}
