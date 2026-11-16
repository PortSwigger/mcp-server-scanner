package com.mcpscanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.access.mining.MinedValueRule;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.DirectIdentityBinding;
import com.mcpscanner.access.IdentityBinding;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.InvokedTools;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.PersistedAccessExpectations;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.MatrixObjectReferences;
import com.mcpscanner.access.comparison.CrossIdentityPorts;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.IdentityIssue;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanSession;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.scan.SendToConnectionPolicy;
import com.mcpscanner.scan.request.RequestGenerator;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

final class AccessWiring {

    private final ExtensionFoundation foundation;
    private final CurrentAuthHolder authHolder;
    private final Supplier<PrincipalRoster> roster;
    private final IdentityListings listings;
    private final PreComparisonDiscovery discovery;
    private final AccessMatrix matrix;
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final AccessLedger ledger;
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "mcp-check-access");
        thread.setDaemon(true);
        return thread;
    }));

    private AccessWiring(ExtensionFoundation foundation, McpScannerSession session, IdentityListings listings,
                         PreComparisonDiscovery discovery) {
        this.discovery = discovery;
        this.foundation = foundation;
        this.authHolder = new CurrentAuthHolder();
        this.roster = new IdentityRosterSource(authHolder, foundation.identities());
        this.listings = listings;
        this.matrix = new AccessMatrix(roster, listings::outcomes,
                new PersistedAccessExpectations(foundation.configStore(), session::resolvedEndpoint));
        this.ledger = new MatrixAccessLedger(matrix, confirmations);
    }

    static AccessWiring create(ExtensionFoundation foundation, ConnectionWiring connection,
                               IdentityListings listings) {
        return create(foundation, connection, listings, PreComparisonDiscovery.NONE);
    }

    static AccessWiring create(ExtensionFoundation foundation, ConnectionWiring connection,
                               IdentityListings listings, PreComparisonDiscovery discovery) {
        AccessWiring wiring = new AccessWiring(foundation, connection.scannerSession(), listings, discovery);
        listings.addListener(wiring.matrix::changed);
        foundation.identities().addListener(wiring.matrix::changed);
        return wiring;
    }

    CurrentAuthHolder authHolder() {
        return authHolder;
    }

    Supplier<PrincipalRoster> roster() {
        return roster;
    }

    IdentityListings listings() {
        return listings;
    }

    PreComparisonDiscovery preComparisonDiscovery() {
        return discovery;
    }

    AccessLedger ledger() {
        return ledger;
    }

    AccessMatrix matrix() {
        return matrix;
    }

    WriteReplayConfirmations confirmations() {
        return confirmations;
    }

    InvokedTools invokedTools() {
        return new InvokedTools(name -> matrix.row(new AccessItemKey(AccessItemKey.Kind.TOOL, name))
                .flatMap(row -> row.item().tool()));
    }

    OwnerRequests sendToOwnerRequests(ConnectionWiring connection, ScanningWiring scanning) {
        McpScannerSession session = connection.scannerSession();
        return new OwnerRequests(primaryRequests(session, scanning, scanning.sendToConnections())::requestFor,
                new IdentityRequests(roster, sendToBinding(connection, scanning.sendToConnections())), minedValues());
    }

    private IdentityBinding sendToBinding(ConnectionWiring connection, SendToConnectionPolicy policy) {
        McpScannerSession session = connection.scannerSession();
        return IdentityBinding.routedWhen(policy::handlesAuthentication, new DirectIdentityBinding(
                StreamingFallback.outsideBurp().around(connection.burpHttp()),
                () -> Optional.ofNullable(session.sessionId()), foundation.eventLog()::warn));
    }

    CheckAccessRunner runner(ConnectionWiring connection, ScanningWiring scanning) {
        return runner(connection, scanning, connection.burpHttp(), siteMapIssues(scanning));
    }

    Consumer<AuditIssue> siteMapIssues(ScanningWiring scanning) {
        return issue -> scanning.engine().addIssuesConsolidatedBy(IdentityIssue::consolidate, List.of(issue));
    }

    CheckAccessRunner runner(ConnectionWiring connection, ScanningWiring scanning, Http http,
                             Consumer<AuditIssue> issueSink) {
        return runner(connection, scanning, http, issueSink, UnaryOperator.identity());
    }

    CheckAccessRunner runner(ConnectionWiring connection, ScanningWiring scanning, Http http,
                             Consumer<AuditIssue> issueSink, UnaryOperator<ScanTarget> ownerTargets) {
        McpRepeaterRequestFactory primaryRequests = auditRequests(connection, scanning);
        OwnerRequests auditRequests = new OwnerRequests(
                target -> primaryRequests.requestFor(ownerTargets.apply(target)), identityRequests(), minedValues());
        return new CheckAccessRunner(comparison(), http, auditRequests, issueSink,
                new WriteReplays(confirmations, ledger), runs, foundation.eventLog(), connection.upstreamExchanges(),
                matrix::snapshot, discovery);
    }

    CrossIdentityComparison comparison() {
        return new CrossIdentityComparison(foundation.eventLog(), authHolder, roster,
                CrossIdentityPorts.of(ledger, listings, new MatrixObjectReferences(matrix, minedValues())));
    }

    McpRepeaterRequestFactory auditRequests(ConnectionWiring connection, ScanningWiring scanning) {
        return primaryRequests(connection.scannerSession(), scanning, connection.sseProxy()::captureScanConnection);
    }

    IdentityRequests identityRequests() {
        return new IdentityRequests(roster);
    }

    private MinedValueRule minedValues() {
        return MinedValueRule.of(new MiningPreferences(foundation.configStore()));
    }

    private static McpRepeaterRequestFactory primaryRequests(McpScannerSession session, ScanningWiring scanning,
                                                             Supplier<ScanConnection> connections) {
        return new McpRepeaterRequestFactory(ScanSession.of(session::resolvedEndpoint, session::scannerHeaders),
                RequestGenerator.standard(), scanning.requestRenderer(), connections);
    }

    List<Runnable> sessionResets() {
        return List.of(runs::cancelAll, matrix::clearOutcomes, confirmations::clear);
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Check access", runs::shutdown);
    }
}
