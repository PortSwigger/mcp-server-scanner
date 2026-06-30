package com.mcpscanner.proxy;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.client.HttpAuthResponses;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpProtocolVersions;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.mcp.SseResponseParser;
import com.mcpscanner.logging.McpEventLog;

class SseScanSession implements Closeable {

    // Hop-by-hop / framing headers that Java's HttpRequest.Builder forbids (matches
    // jdk.internal.net.http.common.Utils.DISALLOWED_HEADERS_SET), plus headers we intentionally
    // synthesise on the outbound request and the scanner-internal strip-auth sentinel.
    // Keep in sync with SseProxyServer.RESERVED_FORWARD_HEADERS — both sets guard the same
    // class of JDK HttpRequest.Builder header-append duplication for their respective
    // forward paths (SSE vs Streamable HTTP). "accept" is included here even though
    // postToMessageEndpoint does not currently hardcode it, so that adding Accept later
    // cannot silently introduce a duplicate-header regression.
    private static final Set<String> RESERVED_REQUEST_HEADERS = Set.of(
            "connection", "content-length", "content-type", "accept", "date",
            "expect", "from", "host", "upgrade", "via", "warning",
            "keep-alive", "te", "trailers",
            ScannerSentinels.STRIP_AUTH_HEADER.toLowerCase());

    private static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration DEFAULT_HANDSHAKE_TIMEOUT = Duration.ofSeconds(5);
    private static final String MCP_PROTOCOL_VERSION = McpProtocolVersions.SCANNER;
    private static final String MCP_CLIENT_NAME = "mcp-scanner-burp";
    private static final String MCP_CLIENT_VERSION = ExtensionMetadata.VERSION;

    // Bounded to prevent unbounded growth when responses arrive for ids that will
    // never be waited on (cancelled scans, timed-out callers). 256 comfortably
    // exceeds Burp's default scanner concurrency.
    static final int PENDING_RESPONSE_CAP = 256;

    private final String sseUrl;
    private final Map<String, String> authHeaders;
    // SSE keeps JDK HttpClient: api.http() is synchronous and cannot consume an open
    // text/event-stream; Montoya exposes no proxy-listener endpoint.
    private final HttpClient httpClient;
    private final Duration responseTimeout;
    private final Duration handshakeTimeout;
    private final LongSupplier handshakeIdAllocator;
    private final Logging logging;
    private final McpEventLog eventLog;
    private final RedirectLoggingInterceptor redirectInterceptor;

    // dispatchLock serialises the (waiter-register OR buffered-response-consume)
    // pair with the reader's (waiter-complete OR response-buffer) pair. Without
    // this, a 2-thread interleaving of the 4 statements could drop a response.
    private final Object dispatchLock = new Object();
    private final ConcurrentMap<String, CompletableFuture<String>> waiters = new ConcurrentHashMap<>();
    // Insertion-ordered so cap eviction is FIFO.
    private final LinkedHashMap<String, String> pendingResponses = new LinkedHashMap<>();
    private final AtomicReference<Throwable> terminalFailure = new AtomicReference<>();

    private InputStream sseInputStream;
    private BufferedReader sseReader;
    private String messageEndpoint;
    private boolean connected;
    private volatile boolean running;
    private volatile boolean disconnecting;
    private Thread readerThread;

    SseScanSession(String sseUrl,
                   Map<String, String> authHeaders,
                   HttpClient httpClient,
                   LongSupplier handshakeIdAllocator,
                   McpEventLog eventLog,
                   Logging logging) {
        this(sseUrl, authHeaders, httpClient, handshakeIdAllocator,
                DEFAULT_RESPONSE_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT, eventLog, logging);
    }

    SseScanSession(String sseUrl,
                   Map<String, String> authHeaders,
                   HttpClient httpClient,
                   LongSupplier handshakeIdAllocator,
                   Duration responseTimeout,
                   Duration handshakeTimeout,
                   McpEventLog eventLog,
                   Logging logging) {
        this.sseUrl = sseUrl;
        this.authHeaders = authHeaders;
        this.httpClient = httpClient;
        this.handshakeIdAllocator = handshakeIdAllocator;
        this.responseTimeout = responseTimeout;
        this.handshakeTimeout = handshakeTimeout;
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.redirectInterceptor = new RedirectLoggingInterceptor(this.eventLog);
    }

    ProxyResponse forwardRequest(String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        String id = extractJsonRpcId(jsonBody);
        if (id == null) {
            return errorResponse(400, "Request missing JSON-RPC id");
        }

        if (disconnecting) {
            return errorResponse(502, "Session closed");
        }

        if (connected && (!running || terminalFailure.get() != null)) {
            disconnect();
        }
        ProxyResponse authChallenge = ensureConnected();
        if (authChallenge != null) {
            return authChallenge;
        }

        CompletableFuture<String> future = new CompletableFuture<>();
        synchronized (dispatchLock) {
            String buffered = pendingResponses.remove(id);
            if (buffered != null) {
                future.complete(buffered);
            } else {
                waiters.put(id, future);
            }
        }
        try {
            MessagePostResult postResult = postToMessageEndpoint(jsonBody, requestHeaders);
            if (!postResult.isSuccess()) {
                return new ProxyResponse(postResult.statusCode(), "application/json", postResult.body());
            }
            Throwable terminal = terminalFailure.get();
            if (terminal != null && !future.isDone()) {
                future.completeExceptionally(terminal);
            }
            String data = future.get(responseTimeout.toMillis(), TimeUnit.MILLISECONDS);
            return new ProxyResponse(200, "application/json", data);
        } catch (TimeoutException te) {
            logging.logToOutput("Waiter timeout for id=" + id);
            eventLog.warn("SSE waiter timed out for id=" + id);
            return errorResponse(502, "Timed out waiting for SSE response");
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause();
            String message = cause != null && cause.getMessage() != null
                    ? cause.getMessage()
                    : "SSE stream error";
            return errorResponse(502, message);
        } finally {
            waiters.remove(id, future);
        }
    }

    int pendingRequests() {
        return waiters.size();
    }

    int pendingResponseCount() {
        synchronized (dispatchLock) {
            return pendingResponses.size();
        }
    }

    @Override
    public void close() throws IOException {
        disconnect();
    }

    // Returns null on success; returns a ProxyResponse to forward to the caller when the
    // SSE GET stream-open is rejected with an auth challenge (lets SseProxyServer drive
    // refreshAuth + retry instead of mapping the failure to a generic 502).
    private synchronized ProxyResponse ensureConnected() throws IOException, InterruptedException {
        if (connected) {
            return null;
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(sseUrl))
                .GET();
        authHeaders.forEach(builder::header);

        HttpResponse<InputStream> response = redirectInterceptor.sendAndLog(
                httpClient, builder.build(), HttpResponse.BodyHandlers.ofInputStream());

        if (HttpAuthResponses.isAuthChallenge(response.statusCode())) {
            return readAuthChallengeBody(response);
        }

        sseInputStream = response.body();
        sseReader = new BufferedReader(new InputStreamReader(sseInputStream));
        messageEndpoint = readEndpointFromStream(sseReader);
        terminalFailure.set(null);
        running = true;
        startReaderThread();

        try {
            performInitializeHandshake();
        } catch (IOException | InterruptedException | RuntimeException e) {
            disconnect();
            throw e;
        }

        connected = true;
        disconnecting = false;
        logging.logToOutput("SSE scan session connected: endpoint=" + messageEndpoint);
        eventLog.info("SSE scan session connected");
        return null;
    }

    private static ProxyResponse readAuthChallengeBody(HttpResponse<InputStream> response) {
        String body = "";
        try (InputStream stream = response.body()) {
            if (stream != null) {
                body = BoundedBodyReader.readUtf8(stream);
            }
        } catch (IOException ignored) {
        }
        return new ProxyResponse(response.statusCode(), "application/json", body);
    }

    private void performInitializeHandshake() throws IOException, InterruptedException {
        String initializeId = String.valueOf(handshakeIdAllocator.getAsLong());
        CompletableFuture<String> waiter = new CompletableFuture<>();
        synchronized (dispatchLock) {
            String buffered = pendingResponses.remove(initializeId);
            if (buffered != null) {
                waiter.complete(buffered);
            } else {
                waiters.put(initializeId, waiter);
            }
        }
        try {
            MessagePostResult initializePost = postToMessageEndpoint(buildInitializeBody(initializeId), authHeaders);
            requireSuccessfulPost(initializePost, "initialize");
            Throwable terminal = terminalFailure.get();
            if (terminal != null && !waiter.isDone()) {
                waiter.completeExceptionally(terminal);
            }
            waiter.get(handshakeTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            throw new IOException("Timed out waiting for initialize response", te);
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException("Initialize handshake failed: " + cause.getMessage(), cause);
        } finally {
            waiters.remove(initializeId, waiter);
        }

        MessagePostResult notificationPost = postToMessageEndpoint(buildInitializedNotificationBody(), authHeaders);
        requireSuccessfulPost(notificationPost, "notifications/initialized");
    }

    private static void requireSuccessfulPost(MessagePostResult result, String stage) throws IOException {
        if (!result.isSuccess()) {
            throw new IOException("Handshake " + stage + " POST returned status " + result.statusCode()
                    + (result.body() != null && !result.body().isEmpty() ? ": " + result.body() : ""));
        }
    }

    private String buildInitializeBody(String id) throws IOException {
        return McpObjectMapper.INSTANCE.writeValueAsString(Map.of(
                "jsonrpc", "2.0",
                "id", parseIdAsLongOrString(id),
                "method", "initialize",
                "params", Map.of(
                        "protocolVersion", MCP_PROTOCOL_VERSION,
                        "capabilities", Map.of(),
                        "clientInfo", Map.of(
                                "name", MCP_CLIENT_NAME,
                                "version", MCP_CLIENT_VERSION))));
    }

    private String buildInitializedNotificationBody() throws IOException {
        return McpObjectMapper.INSTANCE.writeValueAsString(Map.of(
                "jsonrpc", "2.0",
                "method", "notifications/initialized"));
    }

    private static Object parseIdAsLongOrString(String id) {
        try {
            return Long.parseLong(id);
        } catch (NumberFormatException e) {
            return id;
        }
    }

    private void startReaderThread() {
        readerThread = new Thread(this::readLoop, "SseScanSession-reader-" + sseUrl);
        readerThread.setDaemon(true);
        readerThread.start();
    }

    private void readLoop() {
        logging.logToOutput("SSE reader thread started");
        try {
            while (running) {
                SseResponseParser.SseEvent event = SseResponseParser.readNextEvent(sseReader);
                if (event == null) {
                    exitReader(new IOException("SSE stream closed"));
                    return;
                }
                if (!"message".equals(event.eventType())) {
                    continue;
                }
                dispatchMessageEvent(event.data());
            }
        } catch (IOException e) {
            exitReader(e);
        } catch (Throwable e) {
            exitReader(e);
        }
    }

    private void dispatchMessageEvent(String data) {
        String id = extractJsonRpcId(data);
        if (id == null) {
            return;
        }
        synchronized (dispatchLock) {
            CompletableFuture<String> waiter = waiters.remove(id);
            if (waiter != null) {
                waiter.complete(data);
                return;
            }
            pendingResponses.put(id, data);
            if (pendingResponses.size() > PENDING_RESPONSE_CAP) {
                Iterator<String> it = pendingResponses.keySet().iterator();
                if (it.hasNext()) {
                    String evicted = it.next();
                    it.remove();
                    logging.logToOutput("Evicted oldest orphan response id=" + evicted
                            + " (cap=" + PENDING_RESPONSE_CAP + ")");
                }
            }
        }
    }

    private void exitReader(Throwable cause) {
        running = false;
        terminalFailure.compareAndSet(null, cause);
        int failed = failAllPendingWaiters(cause);
        logging.logToError("SSE reader thread exited (cause=" + cause.getMessage()
                + ", failed-waiters=" + failed + ")");
        eventLog.warn("SSE reader thread exited: " + cause.getMessage()
                + " (failed-waiters=" + failed + ")");
    }

    private int failAllPendingWaiters(Throwable cause) {
        int count = 0;
        for (String key : waiters.keySet()) {
            CompletableFuture<String> waiter = waiters.remove(key);
            if (waiter != null) {
                waiter.completeExceptionally(cause);
                count++;
            }
        }
        return count;
    }

    private String readEndpointFromStream(BufferedReader reader) throws IOException {
        String path = SseResponseParser.extractEndpointUrl(reader);
        if (path == null) {
            throw new IOException("SSE stream closed without sending endpoint event");
        }
        return SseResponseParser.resolveMessageUrl(sseUrl, path);
    }

    private MessagePostResult postToMessageEndpoint(String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(messageEndpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        requestHeaders.forEach((name, value) -> {
            if (!RESERVED_REQUEST_HEADERS.contains(name.toLowerCase())) {
                builder.header(name, value);
            }
        });

        HttpResponse<String> response = redirectInterceptor.sendAndLog(
                httpClient, builder.build(), HttpResponse.BodyHandlers.ofString());
        return new MessagePostResult(response.statusCode(), response.body());
    }

    record MessagePostResult(int statusCode, String body) {
        boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }
    }

    private void disconnect() {
        Thread threadToJoin;
        int failed;
        synchronized (this) {
            if (disconnecting) {
                return;
            }
            disconnecting = true;
            running = false;
            connected = false;
            // Fail waiters BEFORE interrupting the reader so they get a clear
            // "Session closed" cause rather than the reader's interrupt-induced
            // wrapped IOException (first completion wins on CompletableFuture).
            failed = failAllPendingWaiters(new IOException("Session closed"));
            if (sseInputStream != null) {
                try {
                    sseInputStream.close();
                } catch (IOException ignored) {
                }
                sseInputStream = null;
            }
            if (readerThread != null) {
                readerThread.interrupt();
            }
            // Capture and null the thread ref under lock so a second disconnect() call
            // never attempts a double-join.
            threadToJoin = readerThread;
            readerThread = null;
            synchronized (dispatchLock) {
                pendingResponses.clear();
            }
            sseReader = null;
            messageEndpoint = null;
        }
        // Join outside the synchronized block so concurrent forwardRequest callers are not
        // blocked for up to 1 s waiting to acquire 'this' while the reader thread exits.
        if (threadToJoin != null) {
            try {
                threadToJoin.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        logging.logToOutput("SSE scan session disconnected (failed-waiters=" + failed + ")");
        eventLog.info("SSE scan session disconnected" + (failed > 0
                ? " (" + failed + " in-flight request" + (failed == 1 ? "" : "s") + " failed)"
                : ""));
    }

    private ProxyResponse errorResponse(int status, String message) {
        try {
            String body = McpObjectMapper.INSTANCE.writeValueAsString(Map.of("error", message));
            return new ProxyResponse(status, "application/json", body);
        } catch (Exception e) {
            String escaped = message == null ? "error" : message.replace("\\", "\\\\").replace("\"", "\\\"");
            return new ProxyResponse(status, "application/json",
                    "{\"error\":\"" + escaped + "\"}");
        }
    }

    static String extractJsonRpcId(String jsonBody) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(jsonBody);
            if (root == null) {
                return null;
            }
            JsonNode idNode = root.get("id");
            if (idNode == null || idNode.isNull()) {
                return null;
            }
            if (idNode.isNumber() || idNode.isTextual()) {
                return idNode.asText();
            }
            return null;
        } catch (IOException e) {
            return null;
        }
    }
}
