package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.checks.registry.IssueDestination;
import com.mcpscanner.checks.registry.LateIssueRouter;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.scancontext.ScanContext;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.ScanCredit;
import com.mcpscanner.http.ScanQueueBypass;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.access.mining.MinedValueRule;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.mcp.McpRequestNames;
import com.mcpscanner.scan.EngineScans;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.MetaEnvelopeCarriers;
import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.scan.RunningScans;
import com.mcpscanner.scan.ScanDestinations;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.ScanLabels;
import com.mcpscanner.scan.ScanModeSetting;
import com.mcpscanner.scan.SendToConnectionPolicy;
import com.mcpscanner.scan.request.BaseRememberingRenderer;
import com.mcpscanner.scan.request.ScanMessageRenderer;

import java.util.List;
import java.util.function.UnaryOperator;

record ScanningWiring(RequestBuildingWiring requests,
                      CheckCatalog catalog,
                      ScanCheckRegistry checkRegistry,
                      ScanGenerationSettings generationSettings,
                      ScanModeSetting scanModeSetting,
                      McpScanLauncher scanLauncher,
                      IdentityRegistry identities,
                      OwnerArgumentSource scanOwnerArguments,
                      ScanFoundation scan,
                      EngineScans engineScans) {

    static ScanningWiring create(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                                 RequestBuildingWiring requests, AccessWiring access, ScanFoundation scan,
                                 CheckInstrumentation instrumentation,
                                 UnaryOperator<ScanMessageRenderer> launchRenderer,
                                 SignedInConsent signedInConsent) {
        McpScanEngine engine = scan.engine();
        ScanFieldWiring fields = scan.fields();
        IssueDestination siteMap = (check, issues, scanContext) ->
                engine.addIssues(check, issues, scanContext.map(ScanningWiring::credit));
        LateIssueRouter lateIssues = new LateIssueRouter(siteMap);
        CheckCatalog catalog = CheckCatalog.discover(
                checkServices(foundation, scan, connection.scannerSession(), access, lateIssues)
                        .withSignedInConsent(signedInConsent));
        ScanCheckRegistry checkRegistry = new ScanCheckRegistry(catalog, foundation.checkSettings(), foundation.eventLog(),
                instrumentation, connection.upstreamExchanges(), connection.connectionReuse(), siteMap,
                new ScannedLeaves(fields.addedArguments(), fields.metaEnvelopes(),
                        connection.proxyDroppedChanges()::dropsEveryChange),
                ScanQueueBypass.through(connection.burpHttp()));
        lateIssues.routeThrough(checkRegistry);
        checkRegistry.registerWith(api.scanner()::registerActiveScanCheck);
        EngineScans engineScans = engineScans(engine, foundation.identities(), connection.scannerSession());
        McpScanLauncher scanLauncher = scanLauncher(api, foundation, connection, fields, engineScans,
                launchRenderer.apply(new BaseRememberingRenderer(requests.requestRenderer(), connection.launchedBases())),
                checkRegistry::auditStarting,
                access.preComparisonDiscovery());
        connection.clientManager().addConnectionLostListener(
                () -> scanLauncher.failRunningScans(McpClientManager.CONNECTION_LOST));
        return new ScanningWiring(requests, catalog, checkRegistry, fields.generationSettings(),
                new ScanModeSetting(foundation.configStore()), scanLauncher,
                foundation.identities(), scanOwnerArguments(foundation.identities(), foundation.configStore()),
                scan, engineScans);
    }

    CurrentAuthHolder authHolder() {
        return requests.authHolder();
    }

    ScanMessageRenderer requestRenderer() {
        return requests.requestRenderer();
    }

    SendToConnectionPolicy sendToConnections() {
        return requests.sendToConnections();
    }

    McpScanEngine engine() {
        return scan.engine();
    }

    CollaboratorWatch collaboratorWatch() {
        return scan.collaboratorWatch();
    }

    private static ScanCredit credit(ScanContext scan) {
        return new ScanCredit(scan.scanId(), scan.testedRequest());
    }

    private static EngineScans engineScans(McpScanEngine engine, IdentityRegistry identities,
                                           McpScannerSession session) {
        return new EngineScans(engine, new ScanLabels(new LiveScanConnectionFacts(session, identities),
                new McpRequestNames()));
    }

    private static OwnerArgumentSource scanOwnerArguments(IdentityRegistry identities,
                                                          ExtensionConfigStore configStore) {
        return MinedValueRule.of(new MiningPreferences(configStore))
                .argumentsOf(() -> identities.primaryUser().ownedValues().ownerArguments());
    }

    private static McpScanLauncher scanLauncher(MontoyaApi api, ExtensionFoundation foundation,
                                                ConnectionWiring connection, ScanFieldWiring fields,
                                                EngineScans engineScans, ScanMessageRenderer renderer,
                                                Runnable auditStarting, PreComparisonDiscovery discovery) {
        McpEventLog eventLog = foundation.eventLog();
        return new McpScanLauncher(api.logging(), renderer, connection.sseProxy()::captureScanConnection,
                fields.templateExpansions(), fields.addedArguments(), metaEnvelopeCarriers(fields, eventLog),
                ScanDestinations.of(api.scanner(), api.burpSuite(), eventLog, engineScans, auditStarting),
                new RunningScans(eventLog, api.burpSuite()), discovery);
    }

    private static MetaEnvelopeCarriers metaEnvelopeCarriers(ScanFieldWiring fields, McpEventLog eventLog) {
        return new MetaEnvelopeCarriers(fields.metaEnvelopes(),
                fields.generationSettings()::metaEnvelopeFuzzedOnEveryRequest, eventLog);
    }

    private static CheckServices checkServices(ExtensionFoundation foundation, ScanFoundation scan,
                                               McpScannerSession session, AccessWiring access,
                                               LateIssueRouter lateIssues) {
        return new CheckServices(foundation.eventLog(), access.authHolder(), scan.collaboratorWatch(),
                session::probeBaselineService, access.roster(), access.ledger(), access.listings(),
                session::probeSseStreams, lateIssues, scan.fields().burpNativeFields());
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Scan end poller", scanLauncher::shutdown);
    }

    List<Runnable> sessionResets() {
        return List.of(scanLauncher::clearRunningScans, checkRegistry::clearConnectionState);
    }
}
