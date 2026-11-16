package com.mcpscanner.integration;

import com.mcpscanner.access.AccessExpectations;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.comparison.CrossIdentityPorts;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpDiscoveryClient;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.identity.discovery.IdentityListing;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanSession;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.McpRequestRenderer;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.scan.request.ScanRequestRenderer;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.InMemoryPersistedObject;


import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.function.Supplier;


import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

final class CheckAccessFixture implements AutoCloseable {

    static final Principal ALICE = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY,
            () -> bearer("alice"), Optional.of("ALICE-PRIVATE-7f3c"), Map.of("doc_id", "d-alice-0001"));
    static final Principal BOB = new Principal("bob", "bob", PrincipalRole.PEER, () -> bearer("bob"),
            Optional.of("BOB-PRIVATE-91ad"), Map.of("doc_id", "d-bob-0042"));
    static final Principal CAROL = new Principal("carol", "carol", PrincipalRole.LOWER, () -> bearer("carol"),
            Optional.empty(), Map.of());
    static final AccessItemKey HANDBOOK = new AccessItemKey(AccessItemKey.Kind.RESOURCE,
            "notes://team/handbook.md");
    private static final List<String> MODULES = List.of("cross_identity_object", "cross_identity_resource",
            "cross_identity_role", "cross_identity_session");
    private static final PrincipalRoster ROSTER = PrincipalRoster.of(ALICE, List.of(BOB, CAROL));
    private static final List<String> FIXTURE_ITEMS = List.of("get_document", "search_docs", "delete_project",
            "list_users", "whoami", "notes://alice/private.md", "notes://bob/private.md", "notes://team/handbook.md");

    private final ScannerProxyFixture alice;
    private final AccessRuns runs;
    private final AccessMatrix matrix;
    private final CheckAccessRunner runner;
    private AccessRunSummary lastSummary;

    private CheckAccessFixture(ScannerProxyFixture alice, AccessRuns runs, AccessMatrix matrix,
                               CheckAccessRunner runner) {
        this.alice = alice;
        this.runs = runs;
        this.matrix = matrix;
        this.runner = runner;
    }

    static McpCheckItSupport.RunningServer startServer(String mode, String... extraArgs) throws Exception {
        List<String> args = new ArrayList<>(List.of("--default-mode", "safe"));
        MODULES.forEach(module -> args.addAll(List.of("--vuln", module + "=" + mode)));
        args.addAll(List.of(extraArgs));
        return McpCheckItSupport.startServer(args.toArray(String[]::new));
    }

    static CheckAccessFixture prepare(String endpoint) throws Exception {
        Map<String, DiscoveryOutcome> listings = discoverAll(endpoint);
        ScannerProxyFixture alice = ScannerProxyFixture.connect(endpoint, TransportType.STREAMABLE_HTTP);
        AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
        AccessMatrix matrix = new AccessMatrix(() -> ROSTER, () -> listings, new StoredExpectations());
        matrix.setExpectation(HANDBOOK, AccessExpectation.SHARED_BY_DESIGN);
        return new CheckAccessFixture(alice, runs, matrix, runner(alice, matrix, listed(listings), () -> ROSTER, runs,
                PreComparisonDiscovery.NONE));
    }

    enum LateComparedUser { NEVER_DISCOVERED, DISCOVER_CLICKED, DISCOVERED_AUTOMATICALLY }

    static CheckAccessFixture prepareWithComparedUserAddedAfterConnect(String endpoint, LateComparedUser lateUser)
            throws Exception {
        IdentityRegistry registry = new IdentityRegistry(
                new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
        IdentityListings listings = new IdentityListings();
        IdentityDiscoveryService discovery = new IdentityDiscoveryService(registry, CheckAccessFixture::discoverAs,
                listings, Runnable::run, McpEventLog.noop());
        discovery.start();
        ConnectResult aliceCatalog = discoverAs(new McpServerConfig(endpoint, TransportType.STREAMABLE_HTTP,
                new BearerTokenAuthStrategy("alice-token")));
        discovery.onPrimaryConnected(new PrimaryConnection(endpoint, TransportType.STREAMABLE_HTTP, aliceCatalog));
        Identity bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        if (lateUser == LateComparedUser.DISCOVER_CLICKED) {
            discovery.discover(bob.id());
        }
        Principal plainAlice = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY,
                () -> bearer("alice"), Optional.empty(), Map.of());
        Supplier<PrincipalRoster> roster = () -> PrincipalRoster.of(plainAlice,
                registry.compared().stream().map(identity -> new Principal(identity.id(), identity.name(),
                        PrincipalRole.PEER, () -> bearer("bob"), Optional.empty(), Map.of())).toList());
        ScannerProxyFixture alice = ScannerProxyFixture.connect(endpoint, TransportType.STREAMABLE_HTTP);
        AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
        AccessMatrix matrix = new AccessMatrix(roster, listings::outcomes, new StoredExpectations());
        matrix.setExpectation(HANDBOOK, AccessExpectation.SHARED_BY_DESIGN);
        return new CheckAccessFixture(alice, runs, matrix, runner(alice, matrix, listings, roster, runs,
                lateUser == LateComparedUser.DISCOVERED_AUTOMATICALLY ? discovery : PreComparisonDiscovery.NONE));
    }

    AccessRunSummary lastSummary() {
        return lastSummary;
    }

    private static PrincipalListings listed(Map<String, DiscoveryOutcome> listings) {
        return (principalId, item) -> Optional.ofNullable(listings.get(principalId))
                .map(outcome -> ((DiscoveryOutcome.Listed) outcome).listing().lists(item));
    }

    private static ConnectResult discoverAs(McpServerConfig config) {
        McpScannerSession session = new McpScannerSession(McpCheckItSupport.realHttpClient(), McpEventLog.noop());
        session.connect(config);
        try {
            return new McpDiscoveryClient(session).discoverCatalog();
        } finally {
            session.disconnect();
        }
    }

    AccessSnapshot checkAllItems() {
        return check(matrix.snapshot().rows().stream()
                .filter(row -> FIXTURE_ITEMS.contains(row.item().key().name())).toList());
    }

    AccessSnapshot checkEveryItem() {
        return check(matrix.snapshot().rows());
    }

    private AccessSnapshot check(List<AccessRow> fixtureRows) {
        CompletableFuture<AccessRunSummary> finished = new CompletableFuture<>();
        runner.start(fixtureRows, tools -> true, new AccessRunListener() {
            @Override
            public void progress(int done, int total) {
            }

            @Override
            public void finished(AccessRunSummary summary) {
                finished.complete(summary);
            }
        }).orElseThrow();
        await().atMost(Duration.ofMinutes(5)).pollInterval(Duration.ofMillis(20)).until(finished::isDone);
        lastSummary = finished.join();
        assertThat(lastSummary.cancelled()).isFalse();
        return matrix.snapshot();
    }

    @Override
    public void close() {
        runs.shutdown();
        alice.close();
    }

    private static CheckAccessRunner runner(ScannerProxyFixture proxy, AccessMatrix matrix,
                                            PrincipalListings listed, Supplier<PrincipalRoster> roster,
                                            AccessRuns runs, PreComparisonDiscovery discovery) {
        WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
        MatrixAccessLedger ledger = new MatrixAccessLedger(matrix, confirmations);
        AccessComparison comparison = new CrossIdentityComparison(McpEventLog.noop(),
                () -> new BearerTokenAuthStrategy("alice-token"), roster, CrossIdentityPorts.of(ledger, listed));
        McpScannerSession alice = proxy.session();
        McpRepeaterRequestFactory primary = new McpRepeaterRequestFactory(
                ScanSession.of(alice::resolvedEndpoint, alice::scannerHeaders), RequestGenerator.standard(),
                new ScanRequestRenderer(parsed(new McpHttpRequestFactory(alice::nextRequestId, alice)),
                        new ClientRegistrationRequestFactory()),
                () -> ScanConnection.unbound(baseline -> withAliceCredentials(proxy.proxy().auditHeaders(baseline))));
        return new CheckAccessRunner(comparison, proxy.routed(new VerbatimHeaderHttp()),
                new OwnerRequests(primary::requestFor, new IdentityRequests(roster)), issue -> { },
                new WriteReplays(confirmations, ledger), runs, McpEventLog.noop(), UpstreamExchanges.NONE,
                matrix::snapshot, discovery);
    }

    private static Map<String, String> withAliceCredentials(Map<String, String> auditHeaders) {
        Map<String, String> headers = new LinkedHashMap<>(auditHeaders);
        headers.putAll(bearer("alice"));
        return headers;
    }

    private static McpRequestRenderer parsed(McpHttpRequestFactory factory) {
        return (endpoint, message, sessionHeaders) -> {
            String[] headAndBody = factory.raw(endpoint, message, sessionHeaders).split("\r\n\r\n", 2);
            Map<String, String> headers = new LinkedHashMap<>();
            Arrays.stream(headAndBody[0].split("\r\n")).skip(1).map(line -> line.split(": ", 2))
                    .filter(header -> !List.of("content-length", "host").contains(header[0].toLowerCase()))
                    .forEach(header -> headers.put(header[0], header[1]));
            return ImmutableHttpRequest.post(endpoint, headers, headAndBody[1]);
        };
    }

    private static Map<String, DiscoveryOutcome> discoverAll(String endpoint) {
        Map<String, DiscoveryOutcome> listings = new LinkedHashMap<>();
        for (Principal principal : List.of(ALICE, BOB, CAROL)) {
            McpScannerSession session = connect(endpoint, principal.name());
            try {
                listings.put(principal.id(), new DiscoveryOutcome.Listed(
                        IdentityListing.of(new McpDiscoveryClient(session).discoverCatalog())));
            } finally {
                session.disconnect();
            }
        }
        return listings;
    }

    private static McpScannerSession connect(String endpoint, String user) {
        McpScannerSession session = new McpScannerSession(McpCheckItSupport.realHttpClient(), McpEventLog.noop());
        session.connect(new McpServerConfig(endpoint, TransportType.STREAMABLE_HTTP,
                new BearerTokenAuthStrategy(user + "-token")));
        return session;
    }

    private static Map<String, String> bearer(String user) {
        return Map.of("Authorization", "Bearer " + user + "-token");
    }

    private static final class StoredExpectations implements AccessExpectations {
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
