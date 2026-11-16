package com.mcpscanner.client;

import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.logging.LogRedaction;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ToLongFunction;

public class McpClientManager {

    public static final String CONNECTION_LOST = "Connection lost: the MCP session ended";

    private static final String COMPLETIONS_CAPABILITY = "completions";
    private static final String NOT_CONNECTED = "Not connected to an MCP server";

    private final McpEventLog eventLog;
    private final McpScannerSession scannerSession;

    private McpDiscoveryClient discoveryClient;
    private volatile ServerMetadata serverMetadata = ServerMetadata.empty();
    private volatile boolean connected;
    private final CopyOnWriteArrayList<Runnable> disconnectListeners = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Runnable> connectionLostListeners = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<PrimaryConnection>> connectListeners = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<List<McpToolDefinition>>> knownToolsListeners =
            new CopyOnWriteArrayList<>();
    private final AtomicBoolean sseProxyAvailable = new AtomicBoolean(true);
    private final OperationRequests operations;
    private volatile ToLongFunction<ResourceCap> resourceCaps = ResourceCap::defaultValue;

    public McpClientManager(McpEventLog eventLog) {
        this(eventLog, ClientIdentityProvider.defaults(), JdkProtocolHttpTransport::new);
    }

    public McpClientManager(McpEventLog eventLog, ClientIdentityProvider identityProvider,
                            ProtocolHttpTransport httpTransport) {
        this(eventLog, identityProvider, httpClient -> httpTransport);
    }

    McpClientManager(McpEventLog eventLog, McpScannerSession scannerSession) {
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.operations = new OperationRequests(eventLog);
        this.scannerSession = Objects.requireNonNull(scannerSession, "scannerSession");
    }

    private McpClientManager(McpEventLog eventLog, ClientIdentityProvider identityProvider,
                             Function<HttpClient, ProtocolHttpTransport> transportFactory) {
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.operations = new OperationRequests(eventLog);
        HttpClient httpClient = McpHttpClients.upstream();
        this.scannerSession = new McpScannerSession(httpClient, operations.counting(transportFactory.apply(httpClient)), eventLog,
                sseProxyAvailable::get, identityProvider);
    }

    public void setSseProxyAvailable(boolean available) {
        sseProxyAvailable.set(available);
    }

    public McpScannerSession scannerSession() {
        return scannerSession;
    }

    public void applySessionSettings(ScannerSessionSettings settings) {
        settings.applyTo(scannerSession);
        setResourceCaps(settings.resourceCaps());
    }

    public void setResourceCaps(ToLongFunction<ResourceCap> resourceCaps) {
        this.resourceCaps = Objects.requireNonNull(resourceCaps);
    }

    public ConnectResult connect(McpServerConfig config) {
        disconnect();
        try {
            return connectAndDiscover(config);
        } catch (RuntimeException error) {
            clearConnectionStateAfterFailure();
            throw error;
        }
    }

    private synchronized ConnectResult connectAndDiscover(McpServerConfig config) {
        operations.measure("Connect", () -> scannerSession.connect(config));
        discoveryClient = new McpDiscoveryClient(scannerSession, eventLog, resourceCaps);
        eventLog.info("Connected to MCP server: " + LogRedaction.redactQuery(config.endpoint()));
        if (config.transport() == TransportType.SSE) {
            eventLog.info("SSE message endpoint: " + LogRedaction.redactQuery(scannerSession.resolvedEndpoint()));
        }
        ConnectResult catalog = operations.measure("Discovery",
                () -> discoveryClient.discoverCatalog(this::notifyKnownTools));
        eventLog.info(formatDiscoverySummary(catalog.tools().size(), catalog.resources().size(),
                catalog.resourceTemplates().size(), catalog.prompts().size()));
        serverMetadata = catalog.serverMetadata();
        connected = true;
        notifyConnect(new PrimaryConnection(config.endpoint(),
                Objects.requireNonNullElse(scannerSession.transportType(), config.transport()), catalog));
        return catalog;
    }

    public void addConnectListener(Consumer<PrimaryConnection> listener) {
        connectListeners.add(Objects.requireNonNull(listener, "listener"));
    }

    public void addKnownToolsListener(Consumer<List<McpToolDefinition>> listener) {
        knownToolsListeners.add(Objects.requireNonNull(listener, "listener"));
    }

    private void notifyKnownTools(List<McpToolDefinition> tools) {
        for (Consumer<List<McpToolDefinition>> listener : knownToolsListeners) {
            try {
                listener.accept(tools);
            } catch (RuntimeException e) {
                eventLog.warn("Known tools listener failed: " + e.getMessage());
            }
        }
    }

    private void notifyConnect(PrimaryConnection connection) {
        for (Consumer<PrimaryConnection> listener : connectListeners) {
            try {
                listener.accept(connection);
            } catch (RuntimeException e) {
                eventLog.warn("Connect listener failed: " + e.getMessage());
            }
        }
    }

    private static String formatDiscoverySummary(int tools, int resources, int templates, int prompts) {
        return "Discovered " + plural(tools, "tool")
                + ", " + plural(resources, "resource")
                + ", " + plural(templates, "resource template")
                + ", " + plural(prompts, "prompt");
    }

    private static String plural(int count, String singular) {
        return count + " " + singular + (count == 1 ? "" : "s");
    }


    public CompletionOutcome complete(CompletionRequest request) {
        if (!connected) {
            return new CompletionOutcome.Failed(NOT_CONNECTED);
        }
        if (!completionsAdvertised()) {
            return new CompletionOutcome.NotAdvertised();
        }
        return new McpCompletionClient(scannerSession).complete(request);
    }

    public boolean completionsAdvertised() {
        Map<String, Object> capabilities = serverMetadata.capabilities();
        return connected && capabilities != null && capabilities.containsKey(COMPLETIONS_CAPABILITY);
    }

    public void disconnect() {
        boolean wasConnected;
        synchronized (this) {
            wasConnected = connected;
            forgetConnection();
        }
        scannerSession.disconnect();
        if (wasConnected) {
            eventLog.info("Disconnected from MCP server");
            notifyDisconnect();
        }
    }


    public void addConnectionLostListener(Runnable listener) {
        connectionLostListeners.add(Objects.requireNonNull(listener, "listener"));
    }

    public void connectionLost() {
        if (!connected) {
            return;
        }
        for (Runnable listener : connectionLostListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                eventLog.warn("Connection-lost listener failed: " + e.getMessage());
            }
        }
        disconnect();
    }

    public void addDisconnectListener(Runnable listener) {
        if (listener != null) {
            disconnectListeners.add(listener);
        }
    }

    public void removeDisconnectListener(Runnable listener) {
        if (listener != null) {
            disconnectListeners.remove(listener);
        }
    }

    private void notifyDisconnect() {
        for (Runnable listener : disconnectListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                eventLog.warn("Disconnect listener failed: " + e.getMessage());
            }
        }
    }

    public void shutdown() {
        disconnect();
    }

    public boolean isConnected() {
        return connected;
    }

    private void clearConnectionStateAfterFailure() {
        synchronized (this) {
            forgetConnection();
        }
        scannerSession.disconnect();
        notifyKnownTools(List.of());
    }

    private void forgetConnection() {
        connected = false;
        discoveryClient = null;
        serverMetadata = ServerMetadata.empty();
    }
}
