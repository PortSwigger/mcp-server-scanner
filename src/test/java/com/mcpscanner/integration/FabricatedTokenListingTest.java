package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.AccessExpectations;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.CheckAccessOptions;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.SyntheticCallLog;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.comparison.CrossIdentityPorts;
import com.mcpscanner.access.listing.ListedPrincipals;
import com.mcpscanner.access.listing.ToolListingAudit;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.client.IsolatedCatalogDiscovery;
import com.mcpscanner.client.JdkProtocolHttpTransport;
import com.mcpscanner.client.McpHttpClients;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.RecordedCatalog;
import com.mcpscanner.client.ScannerSessionSettings;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static org.assertj.core.api.Assertions.assertThat;

class FabricatedTokenListingTest {

    private static final AuthStrategy ALICE_KEY = new BearerTokenAuthStrategy("alice-token");
    private static final Principal ALICE = Principal.primary(ALICE_KEY::headers);
    private static final PrincipalRoster ROSTER = PrincipalRoster.of(ALICE, List.of());

    private final List<AuditIssue> issues = new CopyOnWriteArrayList<>();
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void stopRuns() {
        runs.shutdown();
    }

    @Test
    void anUnknownKeyMappedToAServiceAccountRaisesTheFakeTokenIssueConfirmedByItsCall() throws Exception {
        try (ServiceAccountFixtureServer server = ServiceAccountFixtureServer.unknownKeyFallsBackToServiceAccount()) {
            AccessRunSummary summary = checkAccess(server.endpoint(), TransportType.STREAMABLE_HTTP);

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo("MCP fake token lists tools the primary user does not list");
                assertThat(toolsListEvidence(issue)).extracting(exchange -> exchange.request().method())
                        .containsExactly("POST", "POST");
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
                assertThat(issue.detail()).contains("delete_user, list_users");
                assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().bodyToString())
                        .anyMatch(body -> body.contains("tools/call") && body.contains("list_users"));
                assertThat(issue.requestResponses()).extracting(HttpRequestResponse::request)
                        .extracting(request -> request.headerValue("Authorization"))
                        .contains("Bearer alice-token");
            });
            assertThat(summary.issues()).isEqualTo(1);
            assertThat(server.calls).contains("svc-internal:list_users");
        }
    }

    @Test
    void overLegacySseEachListingIsEvidencedByItsPostThenTheStreamEventThatAnsweredIt() throws Exception {
        try (ServiceAccountFixtureServer server = ServiceAccountFixtureServer.unknownKeyFallsBackToServiceAccount()) {
            checkAccess(server.endpoint(), TransportType.SSE);

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo("MCP fake token lists tools the primary user does not list");
                assertThat(issue.requestResponses()).hasSizeGreaterThanOrEqualTo(4);
                List<HttpRequestResponse> evidence = issue.requestResponses().subList(0, 4);
                assertThat(evidence).extracting(exchange -> exchange.request().method())
                        .containsExactly("POST", "GET", "POST", "GET");
                assertThat(evidence).allSatisfy(exchange -> assertThat(new String(
                        exchange.request().toByteArray().getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1))
                        .contains("Host: 127.0.0.1:", "User-Agent: Java-http-client/")
                        .doesNotContainIgnoringCase("X-Mcp-Scanner-"));
                assertThat(List.of(evidence.get(0), evidence.get(2))).allSatisfy(post -> {
                    assertThat(post.request().path()).startsWith("/messages?session=");
                    assertThat(post.request().bodyToString()).contains("tools/list");
                    assertThat(post.response().statusCode()).isEqualTo((short) 202);
                });
                assertThat(List.of(evidence.get(1), evidence.get(3))).allSatisfy(stream -> {
                    assertThat(stream.request().url()).isEqualTo(server.endpoint());
                    assertThat(stream.response().headerValue("Content-Type")).isEqualTo("text/event-stream");
                    assertThat(stream.response().bodyToString()).startsWith("event: message\n")
                            .containsOnlyOnce("data:").contains("\"tools\"");
                });
                assertThat(evidence.get(1).response().bodyToString()).contains("whoami").doesNotContain("list_users");
                assertThat(evidence.get(3).response().bodyToString()).contains("list_users", "delete_user");
            });
        }
    }

    @Test
    void aServerRejectingUnknownKeysStaysSilent() throws Exception {
        try (ServiceAccountFixtureServer server = ServiceAccountFixtureServer.unknownKeyRejected()) {
            AccessRunSummary summary = checkAccess(server.endpoint(), TransportType.STREAMABLE_HTTP);

            assertThat(issues).isEmpty();
            assertThat(summary.issues()).isZero();
            assertThat(summary.checked()).isPositive();
        }
    }

    private static List<HttpRequestResponse> toolsListEvidence(AuditIssue issue) {
        return issue.requestResponses().stream()
                .filter(exchange -> !exchange.request().bodyToString().contains("tools/call")).toList();
    }

    private AccessRunSummary checkAccess(String endpoint, TransportType transport) {
        IsolatedCatalogDiscovery isolated = new IsolatedCatalogDiscovery(McpEventLog.noop(),
                ClientIdentityProvider.defaults(), new JdkProtocolHttpTransport(McpHttpClients.upstream()),
                ScannerSessionSettings.defaults());
        SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> ALICE_KEY);
        IdentityListings listings = new IdentityListings();
        IdentityDiscoveryService discovery = new IdentityDiscoveryService(new IdentityRegistry(
                new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop())),
                isolated::discoverRecorded, listings, Runnable::run, McpEventLog.noop(), synthetic);
        discovery.start();
        RecordedCatalog primary = isolated.discoverRecorded(new McpServerConfig(endpoint, transport, ALICE_KEY));
        discovery.onPrimaryConnected(new PrimaryConnection(endpoint, transport, primary.catalog(),
                primary.toolsList()));
        AccessMatrix matrix = new AccessMatrix(() -> ROSTER, listings::outcomes, new Expectations(),
                synthetic.all());
        WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
        MatrixAccessLedger ledger = new MatrixAccessLedger(matrix, confirmations);
        SyntheticCallLog calls = new SyntheticCallLog();
        AccessComparison comparison = new CrossIdentityComparison(McpEventLog.noop(), () -> ALICE_KEY, () -> ROSTER,
                CrossIdentityPorts.of(ledger, listings), synthetic::all, calls);
        CheckAccessRunner runner = new CheckAccessRunner(comparison, new VerbatimHeaderHttp(),
                new OwnerRequests(target -> ownerCall(endpoint, target), new IdentityRequests(() -> ROSTER)),
                issues::add, new WriteReplays(confirmations, ledger), runs, McpEventLog.noop(),
                CheckAccessOptions.DEFAULTS.withResults(matrix::snapshot)
                        .withDiscovery(discovery.withSyntheticListings()).withListingAudit(
                        new ToolListingAudit(new ListedPrincipals(() -> ROSTER, synthetic::all, listings::outcomes),
                                calls, discovery::toolsListExchanges, () -> endpoint)));
        CompletableFuture<AccessRunSummary> finished = new CompletableFuture<>();
        runner.start(matrix.snapshot().rows(), tools -> true, new AccessRunListener() {
            @Override
            public void progress(int done, int total) {
            }

            @Override
            public void finished(AccessRunSummary summary) {
                finished.complete(summary);
            }
        }).orElseThrow();
        return valueWithin(Duration.ofSeconds(30), finished);
    }

    private static HttpRequest ownerCall(String endpoint, ScanTarget target) {
        Map<String, String> headers = new HashMap<>(ALICE_KEY.headers());
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json, text/event-stream");
        headers.put("MCP-Protocol-Version", "2025-06-18");
        return ImmutableHttpRequest.post(endpoint, headers, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"" + target.identifier() + "\",\"arguments\":{}}}");
    }

    private static final class Expectations implements AccessExpectations {
        private final Map<AccessItemKey, AccessExpectation> stored = new HashMap<>();

        @Override
        public synchronized Optional<AccessExpectation> stored(AccessItemKey item) {
            return Optional.ofNullable(stored.get(item));
        }

        @Override
        public synchronized void store(AccessItemKey item, AccessExpectation expectation) {
            stored.put(item, expectation);
        }
    }
}
