package com.mcpscanner.client;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.Audit;
import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import dev.langchain4j.mcp.client.DefaultMcpClient;
import dev.langchain4j.mcp.client.McpClient;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.client.transport.http.HttpMcpTransport;
import dev.langchain4j.mcp.client.transport.http.StreamableHttpMcpTransport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

public class McpClientManager {

    private final Logging logging;
    private final McpEventLog eventLog;
    private final McpClientFactory clientFactory;
    private final McpScannerSession scannerSession;
    private final DiscoveryResultObserver discoveryObserver;
    private final McpTransportFactory transportFactory;
    private final AuditFactory auditFactory;

    private McpDiscoveryClient discoveryClient;
    private volatile boolean connected;
    private volatile Audit audit;
    private final CopyOnWriteArrayList<Runnable> disconnectListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean sseProxyAvailable = new AtomicBoolean(true);

    @FunctionalInterface
    interface McpClientFactory {
        McpClient create(McpTransport transport);
    }

    /**
     * Seam for injecting an alternative langchain4j {@link McpTransport}. Production
     * code uses {@link #defaultTransportFactory()} which builds the real Streamable
     * HTTP or SSE transport from the supplied {@link McpServerConfig}.
     */
    @FunctionalInterface
    interface McpTransportFactory {
        McpTransport create(McpServerConfig config) throws IOException;
    }

    /**
     * Allocates a fresh Burp {@link Audit} that lives for the lifetime of one MCP session.
     * {@link McpDiscoveryAuditBridge} pushes captured langchain4j discovery exchanges into
     * this Audit so Burp's registered {@link burp.api.montoya.scanner.scancheck.PassiveScanCheck}
     * implementations (notably {@code JsonRpcDiscoveryResponseScanner}) run against them.
     *
     * <p>Returning {@code null} disables the bridge (headless contexts).
     */
    @FunctionalInterface
    public interface AuditFactory {
        Audit create();
    }

    public McpClientManager(Logging logging,
                            DiscoveryResultObserver discoveryObserver,
                            McpEventLog eventLog,
                            AuditFactory auditFactory) {
        this(logging,
                eventLog,
                transport -> DefaultMcpClient.builder()
                        .transport(transport)
                        .clientName(ExtensionMetadata.NAME)
                        .clientVersion(ExtensionMetadata.VERSION)
                        .initializationTimeout(Duration.ofSeconds(30))
                        .toolExecutionTimeout(Duration.ofSeconds(30))
                        .build(),
                HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NORMAL)
                        .build(),
                discoveryObserver,
                defaultTransportFactory(),
                auditFactory);
    }

    public McpClientManager(Logging logging, DiscoveryResultObserver discoveryObserver,
                            McpEventLog eventLog) {
        this(logging, discoveryObserver, eventLog, noOpAuditFactory());
    }

    McpClientManager(Logging logging,
                     McpEventLog eventLog,
                     McpClientFactory clientFactory,
                     HttpClient httpClient) {
        this(logging, eventLog, clientFactory, httpClient, null, defaultTransportFactory(), noOpAuditFactory());
    }

    McpClientManager(Logging logging,
                     McpEventLog eventLog,
                     McpClientFactory clientFactory,
                     HttpClient httpClient,
                     DiscoveryResultObserver discoveryObserver) {
        this(logging, eventLog, clientFactory, httpClient, discoveryObserver, defaultTransportFactory(), noOpAuditFactory());
    }

    McpClientManager(Logging logging,
                     McpEventLog eventLog,
                     McpClientFactory clientFactory,
                     HttpClient httpClient,
                     DiscoveryResultObserver discoveryObserver,
                     McpTransportFactory transportFactory) {
        this(logging, eventLog, clientFactory, httpClient, discoveryObserver, transportFactory, noOpAuditFactory());
    }

    McpClientManager(Logging logging,
                     McpEventLog eventLog,
                     McpClientFactory clientFactory,
                     HttpClient httpClient,
                     DiscoveryResultObserver discoveryObserver,
                     McpTransportFactory transportFactory,
                     AuditFactory auditFactory) {
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.clientFactory = clientFactory;
        this.discoveryObserver = discoveryObserver != null ? discoveryObserver : DiscoveryResultObserver.NO_OP;
        this.transportFactory = transportFactory;
        this.auditFactory = auditFactory == null ? noOpAuditFactory() : auditFactory;
        this.scannerSession = new McpScannerSession(httpClient, logging, eventLog,
                sseProxyAvailable::get);
    }

    /**
     * Records whether the local SSE proxy started. When {@code false}, any attempt to connect
     * over the SSE transport fails fast with a clear error instead of silently doing nothing,
     * because the proxy that the SSE scan path depends on is not running. Streamable HTTP is
     * unaffected.
     */
    public void setSseProxyAvailable(boolean available) {
        sseProxyAvailable.set(available);
    }

    private static AuditFactory noOpAuditFactory() {
        return () -> null;
    }

    private static McpTransportFactory defaultTransportFactory() {
        // langchain4j is a third-party closed transport (url+headers only); not routable through api.http().
        return config -> {
            Map<String, String> authHeaders = config.auth() == null
                    ? Map.of()
                    : (config.auth().headers() != null ? config.auth().headers() : Map.of());
            return switch (config.transport()) {
                case STREAMABLE_HTTP -> StreamableHttpMcpTransport.builder()
                        .url(config.endpoint())
                        .customHeaders(authHeaders)
                        .build();
                case SSE -> HttpMcpTransport.builder()
                        .sseUrl(config.endpoint())
                        .customHeaders(authHeaders)
                        .build();
            };
        };
    }

    public McpScannerSession scannerSession() {
        return scannerSession;
    }

    public synchronized ConnectResult connect(McpServerConfig config) {
        disconnect();

        this.audit = auditFactory.create();
        McpClient newClient = null;
        try {
            CapturingMcpTransport transport = new CapturingMcpTransport(
                    transportFactory.create(config),
                    endpointUri(config),
                    new McpDiscoveryAuditBridge(() -> audit));
            newClient = clientFactory.create(transport);
            this.discoveryClient = new McpDiscoveryClient(newClient, logging, eventLog);
            logging.logToOutput("Connected to MCP server: " + config.endpoint());
            eventLog.info("Connected to MCP server: " + config.endpoint());

            scannerSession.connect(config);
            if (config.transport() == TransportType.SSE) {
                logging.logToOutput("SSE message endpoint: " + scannerSession.resolvedEndpoint());
                eventLog.info("SSE message endpoint: " + scannerSession.resolvedEndpoint());
            }

            // Icons flow from the langchain4j transport (via CapturingMcpTransport), not
            // from raw HTTP — SSE servers reply 202-empty to a direct list-call POST, so
            // a hand-rolled probe would silently drop icons on SSE.
            // Each capturedEnvelope supplier is read *after* its corresponding discover
            // call drives the underlying transport, which is when the captor populates it.
            List<McpToolDefinition> tools = discoveryClient.discoverToolsWithIcons(transport::toolsListResult);
            List<McpResourceDefinition> resources =
                    discoveryClient.discoverResourcesWithIcons(transport::resourcesListResult);
            List<McpResourceTemplateDefinition> resourceTemplates = discoveryClient.discoverResourceTemplates();
            List<McpPromptDefinition> prompts =
                    discoveryClient.discoverPromptsWithIcons(transport::promptsListResult);
            ServerMetadata serverMetadata = discoveryClient.fetchServerMetadata(transport.initializeResult());
            eventLog.info(formatDiscoverySummary(tools.size(), resources.size(),
                    resourceTemplates.size(), prompts.size()));
            publishDiscovery(scannerSession.resolvedEndpoint(), serverMetadata,
                    tools, resources, resourceTemplates, prompts);
            connected = true;
            return new ConnectResult(tools, resources, resourceTemplates, prompts, serverMetadata);
        } catch (RuntimeException | IOException e) {
            clearConnectionStateAfterFailure(newClient);
            if (e instanceof IOException ioe) {
                logging.logToError("Transport creation failed: " + ioe.getMessage());
                eventLog.error("Transport creation failed: " + ioe.getMessage());
                throw new UncheckedIOException("Failed to create transport: " + ioe.getMessage(), ioe);
            }
            throw (RuntimeException) e;
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

    private void publishDiscovery(String endpoint,
                                  ServerMetadata serverMetadata,
                                  List<McpToolDefinition> tools,
                                  List<McpResourceDefinition> resources,
                                  List<McpResourceTemplateDefinition> resourceTemplates,
                                  List<McpPromptDefinition> prompts) {
        if (endpoint == null) {
            return;
        }
        try {
            discoveryObserver.onDiscovery(serverMetadata, tools, resources, resourceTemplates, prompts,
                    httpServiceFor(endpoint));
        } catch (Exception e) {
            logging.logToError("Discovery observer failed: " + e.getClass().getSimpleName()
                    + " " + e.getMessage());
            eventLog.warn("Discovery observer failed: " + e.getClass().getSimpleName()
                    + " " + e.getMessage());
        }
    }

    private static HttpService httpServiceFor(String endpoint) {
        URI uri = URI.create(endpoint);
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
        return HttpService.httpService(uri.getHost(), port, secure);
    }

    public synchronized void disconnect() {
        boolean wasConnected = discoveryClient != null;
        try {
            if (discoveryClient != null) {
                try {
                    discoveryClient.close();
                    logging.logToOutput("Disconnected from MCP server");
                    eventLog.info("Disconnected from MCP server");
                } catch (Exception e) {
                    logging.logToError("Error disconnecting: " + e.getMessage());
                    eventLog.warn("Error disconnecting: " + e.getMessage());
                }
            }
        } finally {
            connected = false;
            discoveryClient = null;
            scannerSession.disconnect();
            deleteAudit();
            if (wasConnected) {
                notifyDisconnect();
            }
        }
    }

    private void deleteAudit() {
        Audit current = audit;
        audit = null;
        if (current == null) {
            return;
        }
        try {
            current.delete();
        } catch (RuntimeException e) {
            eventLog.warn("Audit delete failed: " + e.getClass().getSimpleName());
        }
    }

    private static URI endpointUri(McpServerConfig config) {
        if (config == null || config.endpoint() == null) {
            return null;
        }
        try {
            return URI.create(config.endpoint());
        } catch (IllegalArgumentException e) {
            return null;
        }
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
                logging.logToError("Disconnect listener failed: " + e.getMessage());
                eventLog.warn("Disconnect listener failed: " + e.getMessage());
            }
        }
    }

    public synchronized void shutdown() {
        disconnect();
    }

    public boolean isConnected() {
        return connected;
    }

    private void clearConnectionStateAfterFailure(McpClient newClient) {
        if (newClient != null) {
            try {
                newClient.close();
            } catch (Exception e) {
                eventLog.info("Ignored close failure during connect rollback: " + e.getClass().getSimpleName());
            }
        }
        connected = false;
        discoveryClient = null;
        scannerSession.disconnect();
        deleteAudit();
    }

}
