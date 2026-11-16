package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.checks.registry.IssueDestination;
import com.mcpscanner.checks.registry.LateIssueRouter;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.shared.scancontext.ScanContext;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.ScanCredit;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.access.mining.MinedValueRule;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.mcp.McpRequestNames;
import com.mcpscanner.scan.EngineScans;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.scan.RunningScans;
import com.mcpscanner.scan.ScanDestinations;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.ScanLabels;
import com.mcpscanner.scan.ScanModeSetting;
import com.mcpscanner.scan.SendToConnectionPolicy;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.scan.request.ScanRequestRenderer;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

record ScanningWiring(CurrentAuthHolder authHolder,
                      CheckCatalog catalog,
                      ScanCheckRegistry checkRegistry,
                      ScanGenerationSettings generationSettings,
                      ScanModeSetting scanModeSetting,
                      ScanMessageRenderer requestRenderer,
                      McpScanLauncher scanLauncher,
                      SendToConnectionPolicy sendToConnections,
                      IdentityRegistry identities,
                      OwnerArgumentSource scanOwnerArguments,
                      McpScanEngine engine,
                      EngineScans engineScans) {

    static ScanningWiring create(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                                 AccessWiring access, ScanFieldWiring fields, McpScanEngine engine,
                                 CheckInstrumentation instrumentation,
                                 UnaryOperator<ScanMessageRenderer> launchRenderer) {
        CurrentAuthHolder authHolder = access.authHolder();
        IssueDestination siteMap = (check, issues, scan) ->
                engine.addIssues(check, issues, scan.map(ScanningWiring::credit));
        LateIssueRouter lateIssues = new LateIssueRouter(siteMap);
        CheckCatalog catalog = CheckCatalog.discover(
                checkServices(foundation, connection.scannerSession(), access, lateIssues));
        ScanCheckRegistry checkRegistry = new ScanCheckRegistry(catalog, foundation.checkSettings(), foundation.eventLog(),
                instrumentation, connection.upstreamExchanges(), connection.connectionReuse(), siteMap,
                new AddedLeafProbeCalls(fields.addedArguments()));
        lateIssues.routeThrough(checkRegistry);
        checkRegistry.registerWith(api.scanner()::registerActiveScanCheck);
        ScanMessageRenderer renderer = requestRenderer(connection);
        EngineScans engineScans = engineScans(engine, foundation.identities(), connection.scannerSession());
        McpScanLauncher scanLauncher = scanLauncher(api, foundation, connection, fields, engineScans,
                launchRenderer.apply(renderer), checkRegistry::auditStarting, access.preComparisonDiscovery());
        connection.clientManager().addConnectionLostListener(
                () -> scanLauncher.failRunningScans(McpClientManager.CONNECTION_LOST));
        return new ScanningWiring(authHolder, catalog, checkRegistry, fields.generationSettings(),
                new ScanModeSetting(foundation.configStore()), renderer, scanLauncher,
                new SendToConnectionPolicy(foundation.configStore()::handleSendToAuthentication,
                        connection.sseProxy()::captureScanConnection, connection.scannerSession()::scannerHeaders),
                foundation.identities(), scanOwnerArguments(foundation.identities(), foundation.configStore()),
                engine, engineScans);
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
                fields.templateExpansions(), fields.addedArguments(), ScanDestinations.of(api.scanner(), api.burpSuite(), eventLog, engineScans,
                        auditStarting),
                new RunningScans(eventLog, api.burpSuite()), discovery);
    }

    private static CheckServices checkServices(ExtensionFoundation foundation, McpScannerSession session,
                                               AccessWiring access, LateIssueRouter lateIssues) {
        return new CheckServices(foundation.eventLog(), access.authHolder(), foundation.collaboratorWatch(),
                session::probeBaselineService, access.roster(), access.ledger(), access.listings(),
                session::probeSseStreams, lateIssues, foundation.burpNativeFields());
    }

    private static ScanMessageRenderer requestRenderer(ConnectionWiring connection) {
        return new ScanRequestRenderer(new McpHttpRequestFactory(connection.scannerSession()::nextRequestId,
                connection.operationFramer())::build,
                new ClientRegistrationRequestFactory());
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Scan end poller", scanLauncher::shutdown);
    }

    List<Runnable> sessionResets() {
        return List.of(authHolder::clear, scanLauncher::clearRunningScans, checkRegistry::clearConnectionState);
    }
}
