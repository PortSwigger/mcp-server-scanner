package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import com.mcpscanner.client.IsolatedCatalogDiscovery;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpHttpClients;
import com.mcpscanner.client.ConnectionLossWatch;
import com.mcpscanner.client.LiveSessionProbe;
import com.mcpscanner.client.PingOutcome;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.client.ScannerSessionSettings;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.ConnectionReusingHttp;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.ParamHeaderFramer;
import com.mcpscanner.mcp.ResendableRequests;
import com.mcpscanner.mcp.ToolParamHeaders;
import com.mcpscanner.proxy.Http1LoopbackRelay;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.proxy.ProxyRouting;
import com.mcpscanner.proxy.ProxySettings;
import com.mcpscanner.proxy.SseProxyServer;
import com.mcpscanner.proxy.UpstreamRecording;

import java.io.IOException;
import java.time.Clock;
import java.util.List;

final class ConnectionWiring {

    private final MontoyaApi api;
    private final ExtensionFoundation foundation;
    private final McpClientManager clientManager;
    private final SseProxyServer sseProxy;
    private final SharedUpstreamTransport upstreamTransport;
    private final UpstreamRecording recording;
    private final ConnectionReuse connectionReuse;
    private final Http burpHttp;
    private final McpOperationFraming.Framer operationFramer;

    private ConnectionWiring(MontoyaApi api, ExtensionFoundation foundation, McpClientManager clientManager, SseProxyServer sseProxy,
                             SharedUpstreamTransport upstreamTransport, UpstreamRecording recording,
                             ConnectionReuse connectionReuse, Http burpHttp,
                             McpOperationFraming.Framer operationFramer) {
        this.api = api;
        this.foundation = foundation;
        this.clientManager = clientManager;
        this.sseProxy = sseProxy;
        this.upstreamTransport = upstreamTransport;
        this.recording = recording;
        this.connectionReuse = connectionReuse;
        this.burpHttp = burpHttp;
        this.operationFramer = operationFramer;
    }

    static ConnectionWiring create(MontoyaApi api, ExtensionFoundation foundation) {
        UpstreamRecording recording = UpstreamRecording.create(foundation.eventLog());
        BoundEndpoint scannerEndpoint = new BoundEndpoint();
        ConnectionReuse connectionReuse = new ConnectionReuse(new ProxyRouting(scannerEndpoint)::answersLocally);
        Http burpHttp = ConnectionReusingHttp.around(api.http(), connectionReuse);
        SharedUpstreamTransport upstreamTransport = SharedUpstreamTransport.over(burpHttp,
                foundation.configStore()::useBurpNetworking, foundation.eventLog(), recording.captures());
        McpClientManager clientManager = clientManager(foundation, upstreamTransport.transport());
        clientManager.scannerSession().observeLegacySseRoutesWith(recording.legacySseRoutes());
        scannerEndpoint.bindTo(clientManager.scannerSession());
        clientManager.addDisconnectListener(connectionReuse::forgetOrigins);
        clientManager.addDisconnectListener(upstreamTransport::forgetStreamingRoutes);
        McpOperationFraming.Framer operationFramer = operationFramer(clientManager, foundation.eventLog());
        return new ConnectionWiring(api, foundation, clientManager,
                sseProxy(clientManager, foundation, upstreamTransport.transport(), recording,
                        operationFramer, resendableRequests(clientManager)),
                upstreamTransport, recording, connectionReuse, burpHttp, operationFramer);
    }

    private static McpOperationFraming.Framer operationFramer(McpClientManager clientManager, McpEventLog eventLog) {
        ToolParamHeaders toolParamHeaders = new ToolParamHeaders(eventLog::warn);
        clientManager.addKnownToolsListener(toolParamHeaders::learn);
        clientManager.addDisconnectListener(toolParamHeaders::forget);
        return new ParamHeaderFramer(clientManager.scannerSession(), toolParamHeaders);
    }

    private static ResendableRequests resendableRequests(McpClientManager clientManager) {
        ResendableRequests resendable = clientManager.scannerSession().resendableRequests();
        clientManager.addKnownToolsListener(resendable::learn);
        clientManager.addDisconnectListener(resendable::forget);
        return resendable;
    }

    private static McpClientManager clientManager(ExtensionFoundation foundation,
                                                  ProtocolHttpTransport upstreamTransport) {
        McpClientManager clientManager = new McpClientManager(foundation.eventLog(), foundation.identityProvider(),
                upstreamTransport);
        clientManager.applySessionSettings(sessionSettings(foundation.configStore()));
        return clientManager;
    }

    static ScannerSessionSettings sessionSettings(ExtensionConfigStore configStore) {
        return new ScannerSessionSettings(configStore::redirectMode, configStore::answerServerPings,
                configStore::useBurpNetworking, configStore::resourceCap);
    }

    private static ConnectionLossWatch connectionLossWatch(McpClientManager clientManager, McpEventLog eventLog) {
        LiveSessionProbe probe = new LiveSessionProbe(() -> clientManager.scannerSession().call("ping", null),
                LiveSessionProbe.DEFAULT_TIMEOUT);
        return new ConnectionLossWatch(ConnectionLossWatch.DEFAULT_THRESHOLD, ConnectionLossWatch.DEFAULT_WINDOW,
                Clock.systemUTC(), () -> ping(clientManager, probe, eventLog),
                ConnectionLossWatch.DEFAULT_CONFIRMING_PINGS,
                ConnectionLossWatch.Pause.of(ConnectionLossWatch.DEFAULT_PING_SPACING),
                ConnectionWiring::startDaemon, clientManager::connectionLost);
    }

    private static PingOutcome ping(McpClientManager clientManager, LiveSessionProbe probe, McpEventLog eventLog) {
        if (!clientManager.isConnected()) {
            return PingOutcome.INCONCLUSIVE;
        }
        PingOutcome outcome = probe.ping();
        eventLog.warn("Repeated forward failures; the scanner session ping result: " + outcome);
        return outcome;
    }

    private static void startDaemon(Runnable task) {
        Thread thread = new Thread(task, "connection-loss-probe");
        thread.setDaemon(true);
        thread.start();
    }

    private static SseProxyServer sseProxy(McpClientManager clientManager, ExtensionFoundation foundation,
                                           ProtocolHttpTransport upstreamTransport, UpstreamRecording recording,
                                           McpOperationFraming.Framer operationFramer,
                                           ResendableRequests resendableRequests) {
        ExtensionConfigStore configStore = foundation.configStore();
        McpScannerSession scannerSession = clientManager.scannerSession();
        return new SseProxyServer(scannerSession, new ProxySettings(
                McpHttpClients.upstream(), upstreamTransport, ProxySettings.DEFAULT_RESPONSE_TIMEOUT, foundation.identityProvider(),
                configStore::redirectMode,
                () -> configStore.resourceCap(ResourceCap.PROXY_POST_BODY_BYTES),
                () -> configStore.resourceCap(ResourceCap.SSE_PENDING_RESPONSE_BYTES),
                configStore::answerServerPings), foundation.toolCallRefusals()::replied, recording, operationFramer,
                resendableRequests, connectionLossWatch(clientManager, foundation.eventLog()));
    }

    McpClientManager clientManager() {
        return clientManager;
    }

    McpScannerSession scannerSession() {
        return clientManager.scannerSession();
    }

    McpOperationFraming.Framer operationFramer() {
        return operationFramer;
    }

    Http burpHttp() {
        return burpHttp;
    }

    ConnectionReuse connectionReuse() {
        return connectionReuse;
    }

    SseProxyServer sseProxy() {
        return sseProxy;
    }

    ProtocolHttpTransport upstreamTransport() {
        return upstreamTransport.transport();
    }

    UpstreamExchanges upstreamExchanges() {
        return recording.store().filingIssuesUnder(recording.legacySseRoutes()::stableUrl);
    }

    IsolatedCatalogDiscovery newIsolatedDiscovery() {
        return new IsolatedCatalogDiscovery(foundation.eventLog(), foundation.identityProvider(),
                upstreamTransport(), sessionSettings(foundation.configStore()));
    }

    void resetOnDisconnect(List<Runnable> resets) {
        resets.forEach(clientManager::addDisconnectListener);
    }

    void start(ShutdownHooks shutdown) {
        shutdown.add("MCP client", clientManager::shutdown);
        try {
            sseProxy.start();
            routeScannerTrafficThroughProxy();
            shutdown.add("SSE proxy", sseProxy::stop);
        } catch (IOException e) {
            reportProxyUnavailable(e);
        }
        shutdown.add("Burp HTTP transport", upstreamTransport::close);
    }

    private void routeScannerTrafficThroughProxy() {
        scannerSession().setSseProxyPort(sseProxy::port);
        resetOnDisconnect(List.of(sseProxy::resetScanSession));
        api.http().registerHttpHandler(new McpHttpHandler(scannerSession(), sseProxy,
                new Http1LoopbackRelay(api.http())));
    }

    private void reportProxyUnavailable(IOException e) {
        clientManager.setSseProxyAvailable(false);
        foundation.eventLog().error("SSE transport unavailable: the local SSE proxy failed to start ("
                + e.getMessage() + "). The Streamable HTTP transport is unaffected.");
    }
}
