package com.mcpscanner.proxy;

import com.mcpscanner.mcp.LegacySseRoutes;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.logging.LogRedaction;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.InFlightServerPings;
import com.mcpscanner.core.protocol.McpRequests;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

class SseScanSession implements Closeable {

    private static final long READER_JOIN_MILLIS = 1000;
    private static final String HANDSHAKE_TIMEOUT = "Timed out waiting for SSE endpoint or initialize response";

    private final String sseUrl;
    private final Map<String, String> authHeaders;
    // SSE keeps JDK HttpClient: api.http() is synchronous and cannot consume an open
    // text/event-stream; Montoya exposes no proxy-listener endpoint.
    private final HttpClient httpClient;
    private final Duration responseTimeout;
    private final Duration handshakeTimeout;
    private final McpEventLog eventLog;
    private final RedirectLoggingInterceptor redirectInterceptor;
    private final SseReplyDispatcher replies;
    private final SseSessionHandshake handshake;
    private final SessionLifecycle lifecycle = new SessionLifecycle();
    private final SseMessagePoster poster;
    private final SseStreamReader streamReader;
    private final InFlightServerPings inFlightPings;
    private final UpstreamCaptures captures;
    private final LegacySseRoutes legacySseRoutes;
    private final MalformedRequestWaits malformedRequestWaits;
    private final Object connectionLock = new Object();
    private RedirectMode sessionRedirectMode;
    private Thread connectingThread;
    private Object handshakeAttempt;
    private String messageEndpoint;
    private volatile boolean connected;

    SseScanSession(String sseUrl, Map<String, String> authHeaders, SseSessionContext context) {
        this.sseUrl = sseUrl;
        this.authHeaders = SseRequestHeaders.forwardable(authHeaders);
        this.httpClient = context.httpClient();
        this.responseTimeout = context.responseTimeout();
        this.handshakeTimeout = context.handshakeTimeout();
        this.eventLog = context.eventLog();
        this.redirectInterceptor = context.redirects();
        this.captures = context.captures();
        this.legacySseRoutes = context.legacySseRoutes();
        this.malformedRequestWaits = context.malformedRequestWaits();
        this.replies = new SseReplyDispatcher(eventLog, context.pendingResponseBudget());
        this.inFlightPings = new InFlightServerPings(context.serverPings(), this::postServerRequestReply);
        this.streamReader = new SseStreamReader("SseScanSession-reader-" + sseUrl, replies, eventLog, lifecycle,
                inFlightPings::consume);
        this.poster = new SseMessagePoster(httpClient, redirectInterceptor, responseTimeout, lifecycle);
        this.handshake = new SseSessionHandshake(replies, context.requestIds(), context.clientProfile(),
                handshakeTimeout);
    }

    ProxyResponse forwardRequest(String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        String id = SseReplyDispatcher.requestId(jsonBody);
        boolean notification = id == null && McpRequestDetector.isNotificationBody(jsonBody);
        if (id == null && !notification) {
            return errorResponse(400, "Request missing JSON-RPC id");
        }
        if (!lifecycle.isOpen()) {
            return errorResponse(502, "Session closed");
        }
        ProxyResponse refusal = ensureConnected();
        if (refusal != null) {
            return refusal;
        }
        requireCurrentRedirectMode();
        return notification ? postNotification(jsonBody, requestHeaders) : exchange(id, jsonBody, requestHeaders);
    }

    private ProxyResponse postNotification(String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        MessagePostResult posted = postToMessageEndpoint(jsonBody,
                SseRequestHeaders.forOperation(authHeaders, requestHeaders));
        captures.record(posted.exchange());
        return posted.toProxyResponse();
    }

    int pendingRequests() {
        return replies.pendingRequests();
    }

    int pendingResponseCount() {
        return replies.pendingResponseCount();
    }

    long pendingResponseBytes() {
        return replies.pendingResponseBytes();
    }

    @Override
    public void close() throws IOException {
        if (lifecycle.close()) {
            tearDown();
        }
    }

    private ProxyResponse exchange(String id, String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        boolean malformed = JsonRpcEnvelopes.isMalformedRequest(jsonBody);
        CompletableFuture<String> reply = replies.expect(id);
        try {
            MessagePostResult posted = postToMessageEndpoint(jsonBody,
                    SseRequestHeaders.forOperation(authHeaders, requestHeaders));
            if (!posted.isSuccess()) {
                captures.record(posted.exchange());
                return posted.toProxyResponse();
            }
            String json = awaitReply(reply, malformed);
            captures.record(posted.exchange().withResponseBody(asMessageEvent(json)));
            return new ProxyResponse(200, "application/json", json, posted.headers());
        } catch (TimeoutException te) {
            eventLog.warn("SSE waiter timed out for id=" + id);
            if (malformed) {
                malformedRequestWaits.unanswered(eventLog);
            }
            return errorResponse(502, "Timed out waiting for SSE response");
        } catch (ExecutionException ee) {
            return errorResponse(502, streamFailureMessage(ee));
        } finally {
            replies.release(id, reply);
            inFlightPings.callEnded(new McpRequests.Request(jsonBody, Map.of()));
        }
    }

    private String awaitReply(CompletableFuture<String> reply, boolean malformed)
            throws InterruptedException, ExecutionException, TimeoutException {
        if (!malformed) {
            return replies.await(reply, responseTimeout);
        }
        String json = replies.await(reply, malformedRequestWaits.timeout(responseTimeout));
        malformedRequestWaits.answered();
        return json;
    }

    private static byte[] asMessageEvent(String json) {
        return ("event: message\ndata: " + json + "\n\n").getBytes(StandardCharsets.UTF_8);
    }

    private static String streamFailureMessage(ExecutionException failure) {
        Throwable cause = failure.getCause();
        return cause != null && cause.getMessage() != null ? cause.getMessage() : "SSE stream error";
    }

    private ProxyResponse ensureConnected() throws IOException, InterruptedException {
        synchronized (connectionLock) {
            recycleIfDead();
            return connected ? null : connectWithinDeadline();
        }
    }

    private ProxyResponse connectWithinDeadline() throws IOException, InterruptedException {
        Object attempt = new Object();
        AtomicBoolean timedOut = new AtomicBoolean();
        beginAttempt(attempt);
        CompletableFuture.delayedExecutor(handshakeTimeout.toNanos(), TimeUnit.NANOSECONDS)
                .execute(() -> expireHandshake(attempt, timedOut));
        try {
            return connect();
        } catch (IOException | InterruptedException e) {
            if (timedOut.get()) {
                Thread.interrupted();
                throw new IOException(HANDSHAKE_TIMEOUT, e);
            }
            throw e;
        } finally {
            endAttempt(timedOut);
        }
    }

    private synchronized void beginAttempt(Object attempt) throws IOException {
        requireOpen();
        handshakeAttempt = attempt;
        connectingThread = Thread.currentThread();
    }

    private void endAttempt(AtomicBoolean timedOut) {
        synchronized (this) {
            handshakeAttempt = null;
            connectingThread = null;
        }
        if (timedOut.get()) {
            Thread.interrupted();
        }
        if (!connected) {
            recycle();
        }
    }

    private void recycleIfDead() {
        if (connected && (!streamReader.isRunning() || replies.isTerminated())) {
            recycle();
        }
    }

    private void recycle() {
        if (lifecycle.beginRecycle()) {
            tearDown();
            lifecycle.endRecycle();
        }
    }

    private synchronized void expireHandshake(Object attempt, AtomicBoolean timedOut) {
        if (handshakeAttempt != attempt) {
            return;
        }
        timedOut.set(true);
        lifecycle.expire();
        streamReader.halt();
        connected = false;
        connectingThread.interrupt();
        replies.failAll(new IOException(HANDSHAKE_TIMEOUT));
    }

    private ProxyResponse connect() throws IOException, InterruptedException {
        sessionRedirectMode = redirectInterceptor.mode();
        HttpResponse<InputStream> response = openStream();
        BufferedReader endpointReader = streamReader.adopt(response.body());
        if (UpstreamRefusal.isRefusal(response.statusCode())) {
            return SseStreamOpening.refusal(response);
        }
        messageEndpoint = SseStreamOpening.messageEndpoint(endpointReader, response.uri() != null ? response.uri() : URI.create(sseUrl));
        legacySseRoutes.observe(messageEndpoint);
        requireCurrentRedirectMode();
        streamReader.start();
        ProxyResponse rejection = handshake.perform(this::postToMessageEndpoint, authHeaders);
        if (rejection != null) {
            return rejection;
        }
        requireCurrentRedirectMode();
        markConnected();
        eventLog.info("SSE scan session connected: endpoint=" + LogRedaction.redactQuery(String.valueOf(messageEndpoint)));
        return null;
    }

    private HttpResponse<InputStream> openStream() throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(sseUrl))
                .timeout(handshakeTimeout)
                .GET();
        authHeaders.forEach(builder::header);
        return redirectInterceptor.sendAndLog(httpClient, builder.build(), HttpResponse.BodyHandlers.ofInputStream());
    }

    private synchronized void markConnected() throws IOException {
        requireOpen();
        connected = true;
    }

    private void requireOpen() throws IOException {
        if (!lifecycle.isOpen()) {
            throw new IOException("Session closed");
        }
    }

    private MessagePostResult postToMessageEndpoint(String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        requireCurrentRedirectMode();
        inFlightPings.callStarted(new McpRequests.Request(jsonBody, requestHeaders));
        return poster.post(messageEndpoint, jsonBody, requestHeaders);
    }

    private void postServerRequestReply(McpRequests.Request reply) {
        try {
            poster.post(messageEndpoint, reply.body(), reply.headers());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException failure) {
            eventLog.warn("SSE server request reply failed: " + failure.getMessage());
        }
    }

    private void requireCurrentRedirectMode() throws IOException {
        if (sessionRedirectMode != redirectInterceptor.mode()) {
            disconnect();
            throw new IOException("Redirect mode changed; reconnect the SSE session");
        }
    }

    private void disconnect() {
        if (lifecycle.beginDisconnect()) {
            tearDown();
        }
    }

    private void tearDown() {
        int failed;
        Thread reader;
        synchronized (this) {
            streamReader.markStopped();
            connected = false;
            // Waiters fail before the reader is interrupted so they see "Session closed",
            // not the reader's interrupt-induced error: the first completion wins.
            failed = replies.failAll(new IOException("Session closed"));
            interruptOtherThreads();
            reader = streamReader.stop();
            replies.clearBuffered();
            messageEndpoint = null;
        }
        awaitExit(reader);
        eventLog.info("SSE scan session disconnected" + inFlightSummary(failed));
    }

    private void interruptOtherThreads() {
        if (connectingThread != null && connectingThread != Thread.currentThread()) {
            connectingThread.interrupt();
        }
        poster.interruptOtherPosts();
    }

    private static void awaitExit(Thread reader) {
        if (reader == null) {
            return;
        }
        try {
            reader.join(READER_JOIN_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String inFlightSummary(int failed) {
        return failed > 0 ? " (" + failed + " in-flight request" + (failed == 1 ? "" : "s") + " failed)" : "";
    }

    private static ProxyResponse errorResponse(int status, String message) {
        return new ProxyResponse(status, "application/json", JsonErrorBody.of(message));
    }
}
