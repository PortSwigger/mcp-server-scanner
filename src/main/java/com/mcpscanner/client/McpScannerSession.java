package com.mcpscanner.client;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpProtocolVersions;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.SseResponseParser;
import com.mcpscanner.logging.McpEventLog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;

public class McpScannerSession {

    private static final String LOOPBACK = "127.0.0.1";
    private static final String SESSION_HEADER = "Mcp-Session-Id";
    private static final String PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version";
    private static final Duration HTTP_REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration SSE_DISCOVERY_TIMEOUT = Duration.ofSeconds(5);
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private static final long INITIALIZE_REQUEST_ID = 1L;
    private static final long FIRST_SCAN_REQUEST_ID = INITIALIZE_REQUEST_ID + 1L;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Logging logging;
    private final McpEventLog eventLog;
    private final RedirectLoggingInterceptor redirectInterceptor;
    private final SseEndpointDiscoverer sseDiscoverer;
    private final BooleanSupplier sseProxyAvailable;
    // Yields the local SSE proxy's listening port once it has started; -1 until then. Self-issued
    // probe checks read it to retarget their probe baseline at the proxy on SSE (see
    // probeBaselineService) so Http.sendRequest reaches the proxy that lifts the /sse reply.
    private volatile IntSupplier sseProxyPort = () -> -1;

    private String endpoint;
    private String sseUrl;
    private TransportType transportType;
    private AuthStrategy currentAuth;
    private Map<String, String> scannerHeaders = new HashMap<>();
    private InputStream sseStream;
    private String negotiatedProtocolVersion = McpProtocolVersions.SCANNER;
    // Lock-free so scanner threads never block on the session lock just to allocate an id.
    private final AtomicLong requestIdCounter = new AtomicLong(INITIALIZE_REQUEST_ID);

    public McpScannerSession(HttpClient httpClient, Logging logging, McpEventLog eventLog) {
        this(httpClient, logging, eventLog, () -> true);
    }

    public McpScannerSession(HttpClient httpClient, Logging logging, McpEventLog eventLog,
                             BooleanSupplier sseProxyAvailable) {
        this.httpClient = httpClient;
        this.objectMapper = McpObjectMapper.INSTANCE;
        this.logging = logging;
        this.eventLog = eventLog;
        this.redirectInterceptor = new RedirectLoggingInterceptor(eventLog);
        this.sseDiscoverer = new SseEndpointDiscoverer(httpClient, logging, eventLog);
        this.sseProxyAvailable = sseProxyAvailable != null ? sseProxyAvailable : () -> true;
    }

    public McpEventLog eventLog() {
        return eventLog;
    }

    public synchronized void connect(McpServerConfig config) {
        rejectSseWhenProxyUnavailable(config.transport());
        disconnect();
        rejectPlainHttpWithAuth(config.endpoint(), config.auth());

        this.transportType = config.transport();
        this.currentAuth = config.auth();
        this.scannerHeaders = new HashMap<>(authHeaders(config.auth()));

        if (config.transport() == TransportType.SSE) {
            this.sseUrl = config.endpoint();
            this.endpoint = resolveSseMessageEndpoint(config.endpoint(), config.auth());
        } else {
            this.endpoint = config.endpoint();
            // Scan ids start after the fixed initialize id (1) so a scan request never collides
            // with the handshake. The counter then stays monotonic across refreshes.
            requestIdCounter.set(FIRST_SCAN_REQUEST_ID);
            if (!refreshScannerSession()) {
                disconnect();
                throw new IllegalStateException(
                        "Failed to establish scanner session for " + config.endpoint()
                                + " — initialize handshake failed");
            }
        }
    }

    public void disconnect() {
        String sessionIdToTerminate;
        URI endpointToDelete;
        Map<String, String> headersSnapshot;
        synchronized (this) {
            sessionIdToTerminate = activeStreamableSessionId();
            endpointToDelete = endpoint != null ? URI.create(endpoint) : null;
            headersSnapshot = new HashMap<>(scannerHeaders);
            endpoint = null;
            sseUrl = null;
            transportType = null;
            currentAuth = null;
            scannerHeaders.clear();
            negotiatedProtocolVersion = McpProtocolVersions.SCANNER;
            requestIdCounter.set(INITIALIZE_REQUEST_ID);
            closeSseStream();
        }
        if (sessionIdToTerminate != null && endpointToDelete != null) {
            issueSessionDelete(endpointToDelete, sessionIdToTerminate, headersSnapshot);
        }
    }

    private String activeStreamableSessionId() {
        if (transportType != TransportType.STREAMABLE_HTTP) {
            return null;
        }
        return scannerHeaders.get(SESSION_HEADER);
    }

    private void issueSessionDelete(URI target, String sessionId, Map<String, String> headers) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                .timeout(HTTP_REQUEST_TIMEOUT)
                .method("DELETE", HttpRequest.BodyPublishers.noBody());
        headers.forEach(builder::header);
        try {
            redirectInterceptor.sendAndLog(httpClient, builder.build(), HttpResponse.BodyHandlers.discarding());
            eventLog.info("Session DELETE sent: " + redact(sessionId));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            eventLog.warn("Session DELETE interrupted: " + redact(sessionId));
        } catch (Exception e) {
            String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            eventLog.warn("Session DELETE failed: " + reason);
        }
    }

    public synchronized String resolvedEndpoint() {
        return endpoint;
    }

    public void setSseProxyPort(IntSupplier sseProxyPort) {
        this.sseProxyPort = sseProxyPort != null ? sseProxyPort : () -> -1;
    }

    /**
     * The {@link HttpService} a self-issued probe should target so its reply is readable.
     *
     * <p>On SSE the upstream {@code /messages} endpoint answers a POST with a bare {@code 202
     * Accepted} (the JSON-RPC reply is delivered out-of-band on the {@code /sse} stream), so a probe
     * sent straight there reads an empty body. Returning the local proxy here makes
     * {@code Http.sendRequest} land on {@link com.mcpscanner.proxy.SseProxyServer}, which owns the
     * stream, correlates the reply by id, and hands back a real JSON response. On Streamable HTTP the
     * upstream already answers inline, so this is empty and the probe baseline is left unchanged.
     */
    public synchronized Optional<HttpService> probeBaselineService() {
        int port = sseProxyPort.getAsInt();
        if (transportType != TransportType.SSE || port <= 0) {
            return Optional.empty();
        }
        return Optional.of(HttpService.httpService(LOOPBACK, port, false));
    }

    public synchronized String sseUrl() {
        return sseUrl;
    }

    public synchronized TransportType transportType() {
        return transportType;
    }

    public synchronized Map<String, String> scannerHeaders() {
        return Collections.unmodifiableMap(new HashMap<>(scannerHeaders));
    }

    public long nextRequestId() {
        return requestIdCounter.getAndIncrement();
    }

    public synchronized boolean refreshAuth() {
        if (currentAuth == null || !currentAuth.supportsRefresh()) {
            return false;
        }
        if (currentAuth.isTerminallyFailed()) {
            return false;
        }
        eventLog.info("Auth refresh attempted after 401");
        if (!currentAuth.refresh()) {
            eventLog.warn("Auth refresh failed");
            return false;
        }
        authHeaders(currentAuth).forEach(scannerHeaders::put);
        eventLog.info("Auth refresh succeeded");
        return true;
    }

    public synchronized boolean refreshScannerSession() {
        if (endpoint == null || transportType != TransportType.STREAMABLE_HTTP) {
            return false;
        }
        // Do NOT reset requestIdCounter here: a 401-triggered refresh mid-scan must keep ids
        // monotonic so it never re-issues a JSON-RPC id already in flight (duplicate-id bug).
        try {
            handshakeStreamableHttp(URI.create(endpoint), authHeaders(currentAuth), HTTP_REQUEST_TIMEOUT);
            scannerHeaders.put(PROTOCOL_VERSION_HEADER, negotiatedProtocolVersion);
            return true;
        } catch (Exception e) {
            logging.logToError("Failed to establish scanner session: " + e.getClass().getSimpleName());
            eventLog.error("Failed to establish scanner session: " + e.getClass().getSimpleName());
            return false;
        }
    }

    private void handshakeStreamableHttp(URI target, Map<String, String> authHeaders, Duration timeout)
            throws IOException, InterruptedException {
        HttpResponse<InputStream> response = sendInitialize(target, authHeaders, timeout);
        try {
            requireSuccessStatus(response.statusCode());
            Optional<String> sessionId = response.headers().firstValue("mcp-session-id");
            negotiateProtocolVersion(response);
            sendInitializedNotification(target, sessionId.orElse(null), authHeaders, timeout);
            if (sessionId.isPresent()) {
                scannerHeaders.put(SESSION_HEADER, sessionId.get());
                logging.logToOutput("Scanner session established: " + redact(sessionId.get()));
                eventLog.info("Scanner session established: " + redact(sessionId.get()));
            } else {
                scannerHeaders.remove(SESSION_HEADER);
                eventLog.info("Server omitted Mcp-Session-Id; scanner will operate statelessly");
            }
        } finally {
            closeQuietly(response.body());
        }
    }

    private void negotiateProtocolVersion(HttpResponse<InputStream> response) throws IOException {
        String body = readInitializeBody(response);
        Optional<String> parsed = InitializeResponseParser.parseProtocolVersion(body, eventLog);
        if (parsed.isPresent()) {
            negotiatedProtocolVersion = parsed.get();
            eventLog.info("Negotiated MCP protocol version: " + negotiatedProtocolVersion);
        } else {
            negotiatedProtocolVersion = McpProtocolVersions.SCANNER;
            eventLog.info("Server omitted protocolVersion; using default: " + McpProtocolVersions.SCANNER);
        }
    }

    private static String readInitializeBody(HttpResponse<InputStream> response) throws IOException {
        if (isEventStream(response)) {
            // Burp api.http() buffers the full body and cannot consume a keep-alive
            // text/event-stream initialize: the JSON-RPC reply arrives in the first
            // SSE event but the stream is held open for further server→client events, so a
            // read-to-end blocks until the 10s timeout → IOException → connect rolls back.
            // Read incrementally via the JDK client and take the reply from the first SSE event.
            // This MUST stay on the JDK HttpClient — do not route through api.http().
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(response.body(), StandardCharsets.UTF_8));
            String json = SseResponseParser.extractJsonRpcResponse(reader);
            return json != null ? json : "";
        }
        return BoundedBodyReader.readUtf8(response.body());
    }

    private static boolean isEventStream(HttpResponse<InputStream> response) {
        return response.headers().firstValue("Content-Type")
                .map(value -> value.toLowerCase().contains("text/event-stream"))
                .orElse(false);
    }

    private HttpResponse<InputStream> sendInitialize(URI target, Map<String, String> authHeaders, Duration timeout)
            throws IOException, InterruptedException {
        String body = objectMapper.writeValueAsString(Map.of(
                "jsonrpc", "2.0",
                "id", INITIALIZE_REQUEST_ID,
                "method", "initialize",
                "params", Map.of(
                        "protocolVersion", McpProtocolVersions.SCANNER,
                        "capabilities", Map.of(),
                        "clientInfo", Map.of("name", ExtensionMetadata.SCANNER_CLIENT_NAME, "version", ExtensionMetadata.VERSION))));
        HttpRequest request = postRequest(target, body, authHeaders, timeout, null);
        return redirectInterceptor.sendAndLog(httpClient, request, HttpResponse.BodyHandlers.ofInputStream());
    }

    private void sendInitializedNotification(URI target, String sessionId, Map<String, String> authHeaders,
                                             Duration timeout) throws IOException, InterruptedException {
        String body = objectMapper.writeValueAsString(Map.of(
                "jsonrpc", "2.0",
                "method", "notifications/initialized"));
        HttpRequest request = postRequest(target, body, authHeaders, timeout, sessionId);
        HttpResponse<InputStream> response = redirectInterceptor.sendAndLog(
                httpClient, request, HttpResponse.BodyHandlers.ofInputStream());
        closeQuietly(response.body());
    }

    private static HttpRequest postRequest(URI target, String body, Map<String, String> authHeaders,
                                           Duration timeout, String sessionId) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(target)
                .timeout(timeout)
                .header("Content-Type", McpHttpHeaders.CONTENT_TYPE_JSON)
                .header("Accept", McpHttpHeaders.ACCEPT_JSON_AND_SSE)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (sessionId != null) {
            builder.header(SESSION_HEADER, sessionId);
        }
        authHeaders.forEach(builder::header);
        return builder.build();
    }

    private static void requireSuccessStatus(int status) throws IOException {
        if (status < 200 || status >= 300) {
            throw new IOException("Initialize returned non-success status: " + status);
        }
    }

    private static String redact(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "<empty>";
        }
        int previewLength = Math.min(6, secret.length());
        return secret.substring(0, previewLength) + "…";
    }

    private void rejectSseWhenProxyUnavailable(TransportType transport) {
        if (transport != TransportType.SSE || sseProxyAvailable.getAsBoolean()) {
            return;
        }
        eventLog.error("SSE transport unavailable: the local SSE proxy failed to start. "
                + "Use the Streamable HTTP transport, which is unaffected.");
        throw new IllegalStateException(
                "SSE proxy unavailable — the local SSE proxy failed to start, so the SSE transport "
                        + "cannot be used. Streamable HTTP still works.");
    }

    private void rejectPlainHttpWithAuth(String endpointUrl, AuthStrategy auth) {
        if (auth == null || authHeaders(auth).isEmpty()) {
            return;
        }
        URI uri;
        try {
            uri = URI.create(endpointUrl);
        } catch (IllegalArgumentException e) {
            return;
        }
        if (!"http".equalsIgnoreCase(uri.getScheme())) {
            return;
        }
        String host = uri.getHost();
        if (host != null && LOOPBACK_HOSTS.contains(host.toLowerCase())) {
            return;
        }
        throw new IllegalStateException(
                "Refusing to send authentication credentials over cleartext http:// to " + host
                        + " — use https:// or connect to a loopback host");
    }

    private String resolveSseMessageEndpoint(String sseEndpointUrl, AuthStrategy auth) {
        SseEndpointDiscoverer.DiscoveryResult result = sseDiscoverer.discover(
                URI.create(sseEndpointUrl), authHeaders(auth), SSE_DISCOVERY_TIMEOUT);
        this.sseStream = result.sseStream();
        return result.messageUrl().toString();
    }

    private void closeSseStream() {
        if (sseStream != null) {
            try {
                sseStream.close();
            } catch (IOException e) {
                logging.logToError("Error closing SSE stream: " + e.getMessage());
            } finally {
                sseStream = null;
            }
        }
    }

    private static Map<String, String> authHeaders(AuthStrategy auth) {
        if (auth == null) {
            return Collections.emptyMap();
        }
        Map<String, String> headers = auth.headers();
        return headers != null ? headers : Collections.emptyMap();
    }

    private static void closeQuietly(InputStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.close();
        } catch (IOException ignored) {
        }
    }
}
