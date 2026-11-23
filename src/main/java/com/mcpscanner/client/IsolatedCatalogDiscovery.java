package com.mcpscanner.client;

import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;

import java.net.http.HttpClient;
import java.util.Objects;

public final class IsolatedCatalogDiscovery {

    private final McpEventLog eventLog;
    private final ClientIdentityProvider identityProvider;
    private final ProtocolHttpTransport httpTransport;
    private final ScannerSessionSettings settings;
    private final HttpClient sseClient = McpHttpClients.upstream();

    public IsolatedCatalogDiscovery(McpEventLog eventLog, ClientIdentityProvider identityProvider,
                                    ProtocolHttpTransport httpTransport, ScannerSessionSettings settings) {
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.identityProvider = Objects.requireNonNull(identityProvider, "identityProvider");
        this.httpTransport = Objects.requireNonNull(httpTransport, "httpTransport");
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    public ConnectResult discover(McpServerConfig config) {
        return discoverRecorded(config).catalog();
    }

    public RecordedCatalog discoverRecorded(McpServerConfig config) {
        ToolsListRecorder recorder = new ToolsListRecorder(httpTransport);
        McpScannerSession session = newSession(recorder);
        try {
            return new ToolsListRecordings(recorder).record(session, () -> {
                session.connect(config);
                return new McpDiscoveryClient(session, eventLog, settings.resourceCaps()).discoverCatalog();
            });
        } finally {
            session.disconnect();
        }
    }

    private McpScannerSession newSession(ProtocolHttpTransport transport) {
        McpScannerSession session = new McpScannerSession(sseClient, transport, eventLog, () -> true,
                identityProvider);
        settings.applyTo(session);
        return session;
    }
}
