package com.mcpscanner.proxy;

import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.ResendableRequests;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.mcp.StreamingResponseReader;

import com.mcpscanner.client.ConnectionLossWatch;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.RedirectFollowingTransport;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.client.RedirectPolicy;
import com.mcpscanner.client.StaleConnectionResendingTransport;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.scan.ScanConnection;
import fi.iki.elonen.NanoHTTPD;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;

/**
 * Local NanoHTTPD proxy that fronts the upstream MCP server so Burp's scanner sees a bounded
 * HTTP response. Burp's scanner cannot consume streaming replies (chunked {@code text/event-stream}
 * bodies that hold open indefinitely), so for SSE transports this proxy is mandatory: it terminates
 * the SSE stream locally, lifts the JSON-RPC reply out of the {@code event: message} payload, and
 * hands Burp a plain bounded HTTP response.
 *
 * @implNote Do not attempt to replace this with synchronous intercept-and-respond inside
 * {@link McpHttpHandler} (e.g. {@code RequestToBeSentAction.continueWith(...)} with a synthesised
 * response). That refactor has been tried; the handler hook does not fire in time relative to
 * Burp's scanner pipeline, so the request goes out on the wire before the synthesised response is
 * ready. The accepted side effect is that rewritten requests show up in HTTP history pinned to
 * {@code 127.0.0.1:<ephemeral>} and Burp's live-passive task fires against the local host; the
 * active audit we create still carries the real upstream {@code HttpService}.
 */
public class SseProxyServer extends NanoHTTPD {

    private static final String LOOPBACK_HOST = "127.0.0.1";
    private static final int MAX_CONCURRENT_FORWARDS = 32;

    private final McpScannerSession scannerSession;
    private final JsonRpcIdRewriter idRewriter;
    private final BoundedPostBody postBody;
    private final ProvenanceGuard guard;
    private final SseSessionPool sseSessions;
    private final ForwardingStrategy httpForwarding;
    private final ForwardingStrategy sseForwarding;
    private final Semaphore forwardConcurrencyLimiter = new Semaphore(MAX_CONCURRENT_FORWARDS, true);
    private final ConnectAsToolCallTap toolCallReplies;
    private final UpstreamRecording recording;
    private final LoopbackRoutingKey routingKey = LoopbackRoutingKey.mint();
    private final BrowserRequestGuard browserGuard = new BrowserRequestGuard(routingKey);
    private final ConnectionLossWatch lossWatch;

    public SseProxyServer(McpScannerSession scannerSession, ProxySettings settings,
                          ToolCallReplyObserver toolCallReplies, UpstreamRecording recording,
                          McpOperationFraming.Framer operationFramer, ResendableRequests resendableRequests,
                          ConnectionLossWatch lossWatch) {
        this(scannerSession, settings, SseScanSession::new, toolCallReplies, recording, operationFramer,
                resendableRequests, lossWatch);
    }

    SseProxyServer(McpScannerSession scannerSession, ProxySettings settings,
                   SseScanSessionFactory managedSessionFactory, ToolCallReplyObserver toolCallReplies,
                   UpstreamRecording recording, McpOperationFraming.Framer operationFramer,
                   ResendableRequests resendableRequests, ConnectionLossWatch lossWatch) {
        super(LOOPBACK_HOST, 0);
        this.lossWatch = lossWatch;
        this.scannerSession = scannerSession;
        this.recording = recording;
        this.toolCallReplies = new ConnectAsToolCallTap(toolCallReplies);
        this.idRewriter = new JsonRpcIdRewriter(scannerSession::nextRequestId, scannerSession.eventLog());
        this.postBody = new BoundedPostBody(settings.postBodyLimit());
        this.guard = new ProvenanceGuard(scannerSession);
        var redirectPolicy = new RedirectPolicy(scannerSession.eventLog(), settings.redirectMode());
        var serverPings = new ServerPings(settings.answerServerPings());
        var upstream = new UpstreamHttp(new RedirectFollowingTransport(StaleConnectionResendingTransport.whenResendable(
                settings.upstreamTransport(), resendableRequests), redirectPolicy),
                new StreamingResponseReader(settings.responseTimeout()), settings.responseTimeout(), serverPings);
        var requests = new HttpForwardRequests(scannerSession, operationFramer);
        this.httpForwarding = new HttpForwarding(scannerSession, guard, requests, upstream,
                new IsolatedHttpForwarder(scannerSession, guard, requests, upstream, settings.identityProvider()));
        this.sseSessions = new SseSessionPool(scannerSession, guard, managedSessionFactory,
                sessionContext(scannerSession, settings, new RedirectLoggingInterceptor(redirectPolicy), serverPings,
                        recording));
        this.sseForwarding = new SseForwarding(scannerSession, guard, sseSessions);
    }

    private static SseSessionContext sessionContext(McpScannerSession scannerSession, ProxySettings settings,
                                                    RedirectLoggingInterceptor redirects, ServerPings serverPings,
                                                    UpstreamRecording recording) {
        return new SseSessionContext(settings.httpClient(), scannerSession::nextRequestId,
                () -> settings.identityProvider().current().profile(), scannerSession.eventLog(), redirects,
                settings.pendingResponseBudget(), SseSessionContext.DEFAULT_RESPONSE_TIMEOUT,
                SseSessionContext.DEFAULT_HANDSHAKE_TIMEOUT, serverPings, recording.captures(),
                recording.legacySseRoutes(), new MalformedRequestWaits(MalformedRequestWaits.DEFAULT_SHORT_WAIT));
    }

    public int port() {
        return getListeningPort();
    }

    public LoopbackRoutingKey routingKey() {
        return routingKey;
    }

    public Map<String, String> auditHeaders(Map<String, String> baseline) {
        return guard.auditHeaders(baseline);
    }

    public ScanConnection captureScanConnection() {
        ProxyConnection connection = guard.capture();
        return new ScanConnection(baseline -> guard.use(connection, () -> auditHeaders(baseline)),
                () -> guard.use(connection, () -> null));
    }

    @Override
    public Response serve(IHTTPSession session) {
        ProxyConnection connection = guard.capture();
        Response rejection = rejection(session, connection.endpoint());
        if (rejection != null) {
            return rejection;
        }
        try {
            forwardConcurrencyLimiter.acquire();
        } catch (InterruptedException e) {
            return interrupted("Proxy request interrupted while awaiting concurrency slot");
        }
        try {
            return forward(session, connection);
        } finally {
            forwardConcurrencyLimiter.release();
        }
    }

    private Response rejection(IHTTPSession session, String endpoint) {
        if (endpoint == null) {
            return errorResponse(Response.Status.SERVICE_UNAVAILABLE, "MCP server not connected");
        }
        if (session.getMethod() != Method.POST) {
            return rejectUnexpectedRequest(session, statusOf(405), "method " + session.getMethod() + " not allowed");
        }
        if (!isExpectedEndpoint(endpoint, session)) {
            return rejectUnexpectedRequest(session, statusOf(404), "request path does not match resolved MCP endpoint");
        }
        if (browserGuard.refuses(session.getHeaders())) {
            return rejectUnexpectedRequest(session, statusOf(403), BrowserRequestGuard.REFUSAL_REASON);
        }
        return null;
    }

    private Response forward(IHTTPSession session, ProxyConnection connection) {
        try {
            String scannerBody = postBody.read(session);
            Map<String, String> headers = session.getHeaders();
            AuditRequest audit = guard.classify(headers, connection);
            if (audit.status() == AuditProvenance.Status.RETIRED) {
                return expiredAuditResponse();
            }
            return forwardWith(strategyFor(connection), new ScannerRequest(scannerBody, idRewriter.rewrite(scannerBody)),
                    SentinelHeaders.withoutAuditCapability(headers), audit);
        } catch (BoundedPostBody.TooLargeException e) {
            return errorResponse(statusOf(413), "POST body exceeds configured limit");
        } catch (BoundedPostBody.LengthRequiredException e) {
            return errorResponse(statusOf(411), "Bounded POST requires Content-Length");
        } catch (Exception e) {
            return failure(httpForwarding, e);
        }
    }

    private ForwardingStrategy strategyFor(ProxyConnection connection) {
        return connection.transport() == TransportType.SSE ? sseForwarding : httpForwarding;
    }

    private Response forwardWith(ForwardingStrategy strategy, ScannerRequest request, Map<String, String> headers,
                                 AuditRequest audit) {
        try (ForwardCapture capture = recording.open()) {
            ProxyResponse forwarded = forwardUpstream(strategy, request, headers, audit);
            toolCallReplies.observe(request.scannerBody(), headers, audit, forwarded);
            Response response = newFixedLengthResponse(statusOf(forwarded.statusCode()), forwarded.contentType(),
                    idRewriter.restoreId(Objects.requireNonNullElse(forwarded.body(), ""), request.rewrittenBody(),
                            request.scannerBody()));
            forwarded.headers().forEach(response::addHeader);
            recording.keep(capture, request.rewrittenBody())
                    .ifPresent(id -> response.addHeader(ScannerSentinels.EXCHANGE_HEADER, id));
            return response;
        } catch (Exception e) {
            return failure(strategy, e);
        }
    }

    private ProxyResponse forwardUpstream(ForwardingStrategy strategy, ScannerRequest request,
                                          Map<String, String> headers, AuditRequest audit) throws Exception {
        try {
            return strategy.forward(request.rewrittenBody(), headers, audit);
        } catch (ExpiredAuditException | InterruptedException notAnUpstreamFailure) {
            throw notAnUpstreamFailure;
        } catch (Exception upstreamFailure) {
            lossWatch.failed();
            throw upstreamFailure;
        }
    }

    private Response failure(ForwardingStrategy strategy, Exception e) {
        if (e instanceof ExpiredAuditException) {
            return expiredAuditResponse();
        }
        if (e instanceof InterruptedException) {
            return interrupted(strategy.label() + " request interrupted");
        }
        scannerSession.eventLog().warn(strategy.label() + " error: " + e.getMessage());
        return errorResponse(statusOf(502), strategy.label() + " error: " + e.getMessage());
    }

    private Response interrupted(String message) {
        Thread.currentThread().interrupt();
        scannerSession.eventLog().warn(message);
        return errorResponse(statusOf(502), "Request interrupted");
    }

    int concurrencyPermitsAvailable() {
        return forwardConcurrencyLimiter.availablePermits();
    }

    @Override
    public void stop() {
        guard.reset();
        sseSessions.stop();
        super.stop();
    }

    public void resetScanSession() {
        guard.reset();
        sseSessions.closeAll();
    }

    private Response expiredAuditResponse() {
        return errorResponse(statusOf(409), "Audit connection has expired");
    }

    private Response rejectUnexpectedRequest(IHTTPSession session, Response.IStatus status, String reason) {
        scannerSession.eventLog().warn("Local proxy rejected request from "
                + session.getRemoteIpAddress() + " " + session.getMethod() + " " + session.getUri()
                + ": " + reason);
        return errorResponse(status, reason);
    }

    private boolean isExpectedEndpoint(String endpoint, IHTTPSession session) {
        URI target;
        try {
            target = new URI(endpoint);
        } catch (URISyntaxException e) {
            scannerSession.eventLog().warn("Local proxy has malformed configured endpoint \""
                    + endpoint + "\" (extension misconfiguration): " + e.getMessage());
            return false;
        }
        // Path-only, like McpHttpHandler: SSE message URLs carry a varying session_id and fuzzed
        // requests vary the query, so a query match would 404 legitimate traffic.
        return Objects.equals(normalizePath(target.getRawPath()), normalizePath(session.getUri()));
    }

    private static String normalizePath(String path) {
        return (path == null || path.isEmpty()) ? "/" : path;
    }

    private record ScannerRequest(String scannerBody, String rewrittenBody) {}

    private static Response errorResponse(Response.IStatus status, String message) {
        return newFixedLengthResponse(status, "application/json", JsonErrorBody.of(message));
    }

    private static Response.IStatus statusOf(int code) {
        return new Response.IStatus() {
            @Override public String getDescription() { return code + " "; }
            @Override public int getRequestStatus() { return code; }
        };
    }
}
