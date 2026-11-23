package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.scan.CredentialedHeaders;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.RunningScan;
import com.mcpscanner.scan.ScanActivity;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanPlanner;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.scan.request.ServerCapabilities;
import com.mcpscanner.testutil.ClientCertificateBurpHttp;
import com.mcpscanner.testutil.HandlerRoutedBurpHttp;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;

import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

final class WiredExtension implements AutoCloseable {

    static final Duration RUN_BOUND = Duration.ofSeconds(30);

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Http http = mock(Http.class);
    private final List<AuditIssue> siteMap = new CopyOnWriteArrayList<>();
    private final List<String> burpOutput = new CopyOnWriteArrayList<>();
    private final List<String> burpErrors = new CopyOnWriteArrayList<>();
    private final List<String> everyLogLine = new CopyOnWriteArrayList<>();
    private final ShutdownHooks shutdown = new ShutdownHooks(failure -> {
        throw new AssertionError(failure);
    });
    private ExtensionFoundation foundation;
    private ConnectionWiring connection;
    private IdentityWiring identities;
    private IdentityDiscoveryWiring identityDiscovery;
    private AccessWiring access;
    private ScanningWiring scanning;

    private WiredExtension() {
    }

    static WiredExtension sendingThroughBurp() throws Exception {
        return loaded(true);
    }

    static WiredExtension sendingThroughTheJdkClient() throws Exception {
        return loaded(false);
    }

    private static WiredExtension loaded(boolean useBurpNetworking) throws Exception {
        WiredExtension extension = new WiredExtension();
        extension.load(useBurpNetworking);
        return extension;
    }

    private void load(boolean useBurpNetworking) throws Exception {
        renderRequestsAsImmutable();
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        savedSettings.setBoolean("mcp.networking.use_burp", useBurpNetworking);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(api.http()).thenReturn(http);
        Logging logging = recordingLogging();
        when(api.logging()).thenReturn(logging);
        SiteMap burpSiteMap = mock(SiteMap.class);
        when(api.siteMap()).thenReturn(burpSiteMap);
        doAnswer(invocation -> siteMap.add(invocation.getArgument(0))).when(burpSiteMap).add(any(AuditIssue.class));
        when(burpSiteMap.issues(nullable(SiteMapFilter.class))).thenAnswer(invocation -> List.copyOf(siteMap));
        routeThroughBurpRefusingStreams();
        wire();
    }

    MontoyaApi api() {
        return api;
    }

    ExtensionFoundation foundation() {
        return foundation;
    }

    ConnectionWiring connection() {
        return connection;
    }

    IdentityDiscoveryWiring identityDiscovery() {
        return identityDiscovery;
    }

    AccessWiring access() {
        return access;
    }

    ScanningWiring scanning() {
        return scanning;
    }

    List<AuditIssue> siteMap() {
        return siteMap;
    }

    List<String> burpOutput() {
        return List.copyOf(burpOutput);
    }

    List<String> burpErrors() {
        return List.copyOf(burpErrors);
    }

    List<McpEventLog.LogEntry> logEntries() {
        return foundation.eventLog().snapshot();
    }

    List<String> everyLogLineOnceTheScanFinished() {
        await().atMost(RUN_BOUND).until(() -> everyLogLine.stream().anyMatch(line -> line.contains("finished — ")));
        return List.copyOf(everyLogLine);
    }

    List<String> logged() {
        return logEntries().stream().map(McpEventLog.LogEntry::message).toList();
    }

    ScanActivity scanTool(McpToolDefinition tool) {
        McpScannerSession session = connection.scannerSession();
        ScanPlanner planner = new ScanPlanner(scanning.generationSettings(), ServerCapabilities::none,
                session::negotiatedProtocolVersion, AdvertisedAuthorizationServer::none,
                scanning.scanOwnerArguments());
        McpScanLauncher launcher = scanning.scanLauncher();
        access.confirmations().confirm(List.of(tool));
        RunningScan scan = launcher.captureScan(ScanMode.MCP_ONLY, session.resolvedEndpoint(),
                planner.planItem(new ScanTarget.Tool(tool)),
                CredentialedHeaders.of(session::scannerHeaders, access.authHolder().get()),
                launcher.captureConnection()).get();
        await().atMost(RUN_BOUND).until(scan::isFinished);
        return scan.activity();
    }

    @Override
    public void close() {
        shutdown.extensionUnloaded();
    }

    private Logging recordingLogging() {
        Logging logging = mock(Logging.class);
        doAnswer(invocation -> burpOutput.add(invocation.getArgument(0))).when(logging).logToOutput(anyString());
        doAnswer(invocation -> burpErrors.add(invocation.getArgument(0))).when(logging).logToError(anyString());
        return logging;
    }

    private static void renderRequestsAsImmutable() {
        when(ObjectFactoryLocator.FACTORY.httpRequest(any(HttpService.class), anyString()))
                .thenAnswer(call -> parsed(call.getArgument(0), call.getArgument(1)));
    }

    private static HttpRequest parsed(HttpService service, String raw) {
        String[] headAndBody = raw.split("\r\n\r\n", 2);
        String[] lines = headAndBody[0].split("\r\n");
        Map<String, String> headers = new LinkedHashMap<>();
        Arrays.stream(lines).skip(1).map(line -> line.split(": ", 2))
                .filter(header -> !List.of("content-length", "host").contains(header[0].toLowerCase(Locale.ROOT)))
                .forEach(header -> headers.put(header[0], header[1]));
        String url = "http://" + service.host() + ":" + service.port() + lines[0].split(" ")[1];
        return ImmutableHttpRequest.post(url, headers, headAndBody[1]);
    }

    private void routeThroughBurpRefusingStreams() throws Exception {
        HandlerRoutedBurpHttp burp = new HandlerRoutedBurpHttp(this::routedByTheExtensionsHandler,
                ClientCertificateBurpHttp.withoutClientCertificate());
        when(http.sendRequest(any(HttpRequest.class)))
                .thenAnswer(invocation -> burp.sendRequest(invocation.getArgument(0, HttpRequest.class)));
        when(http.sendRequest(any(HttpRequest.class), any(HttpMode.class), anyString()))
                .thenAnswer(invocation -> burp.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, HttpMode.class), invocation.getArgument(2, String.class)));
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> burp.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    private HttpRequest routedByTheExtensionsHandler(HttpRequest request) {
        ArgumentCaptor<HttpHandler> handler = ArgumentCaptor.forClass(HttpHandler.class);
        verify(http, atLeastOnce()).registerHttpHandler(handler.capture());
        return handler.getAllValues().stream().filter(McpHttpHandler.class::isInstance).map(McpHttpHandler.class::cast)
                .findFirst().orElseThrow().route(request);
    }

    private void wire() {
        foundation = ExtensionFoundation.create(api);
        foundation.eventLog().subscribe(entry -> everyLogLine.add(entry.message()));
        connection = ConnectionWiring.create(api, foundation);
        identities = IdentityWiring.create(foundation, OAuthWiring.create(api, foundation, connection.burpHttp()));
        identityDiscovery = IdentityDiscoveryWiring.create(foundation, connection);
        access = AccessWiring.create(foundation, connection, identityDiscovery.listings());
        ScanFoundation scan = ScanFoundation.create(api, foundation, connection);
        scanning = ScanningWiring.create(api, foundation, connection,
                RequestBuildingWiring.create(foundation, connection, access.authHolder()), access, scan,
                CheckInstrumentation.NONE, UnaryOperator.identity(),
                com.mcpscanner.checks.api.SignedInConsent.OPTED_OUT);
        EngineWiring.registerChecks(scan.engine(), scanning.checkRegistry(), shutdown);
        connection.start(shutdown);
        identityDiscovery.addShutdownHooks(shutdown);
        identities.addShutdownHooks(shutdown);
        access.addShutdownHooks(shutdown);
    }
}
