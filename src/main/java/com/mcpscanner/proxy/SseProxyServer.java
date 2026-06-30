package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.client.HttpAuthResponses;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.mcp.SseResponseParser;
import fi.iki.elonen.NanoHTTPD;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;
import java.util.regex.Pattern;

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

    // Bounds the outbound forward's connection setup and time-to-response-headers (the shared
    // HttpClient only sets a connectTimeout), covering the common slow/stalling-upstream case. It
    // does not fully cap a hostile upstream that returns headers immediately and then trickles an
    // endless text/event-stream body — that vector is only loosely bounded here and would need a
    // read-side byte/total cap to fully close. Mirrors SseScanSession.DEFAULT_RESPONSE_TIMEOUT;
    // kept local rather than shared this pass.
    private static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofSeconds(30);

    private static final Pattern SESSION_NOT_FOUND_CODE =
            Pattern.compile("\"code\"\\s*:\\s*-32600");

    // Hop-by-hop and framing headers must never be copied verbatim onto the outbound
    // HttpClient request — Java's HttpRequest.Builder forbids the full DISALLOWED_HEADERS_SET
    // (see jdk.internal.net.http.common.Utils), including keep-alive/te/trailers, and the
    // rest are reserved by RFC 7230 / the HTTP/2 upgrade dance. content-type and accept are
    // included because forwardStreamableHttp hardcodes canonical MCP values for both; allowing
    // the scanner-supplied copies through would produce duplicates (HttpRequest.Builder.header
    // appends, not replaces). Keep in sync with SseScanSession.RESERVED_REQUEST_HEADERS.
    private static final Set<String> RESERVED_FORWARD_HEADERS = caseInsensitiveSet(
            "host", "content-length", "content-type", "accept", "connection", "upgrade",
            "transfer-encoding", "http2-settings", "proxy-connection", "expect",
            "keep-alive", "te", "trailers",
            "authorization");

    // Exhaustive whitelist of scannerHeaders() entries that are NOT auth-bearing; everything
    // else in scannerHeaders() is treated as auth and suppressed when the strip sentinel is set.
    // Any future non-auth header added to scannerHeaders() (e.g. tracing) MUST be added here
    // or auth-bypass probes will silently drop it.
    private static final Set<String> NON_AUTH_SESSION_HEADERS = caseInsensitiveSet(
            "mcp-session-id", "mcp-protocol-version");

    private final McpScannerSession scannerSession;
    private final HttpClient httpClient;
    private final Logging logging;
    private final JsonRpcIdRewriter idRewriter;
    private final Supplier<SseScanSession> sseScanSessionFactory;
    private final RedirectLoggingInterceptor redirectInterceptor;
    private final Semaphore forwardConcurrencyLimiter = new Semaphore(MAX_CONCURRENT_FORWARDS, true);
    private SseScanSession sseScanSession;

    public SseProxyServer(McpScannerSession scannerSession, Logging logging) {
        // SSE keeps JDK HttpClient: api.http() is synchronous and cannot consume an open
        // text/event-stream; Montoya exposes no proxy-listener endpoint.
        this(scannerSession, HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build(), logging);
    }

    SseProxyServer(McpScannerSession scannerSession, HttpClient httpClient, Logging logging) {
        this(scannerSession, httpClient, null, logging, null);
    }

    SseProxyServer(McpScannerSession scannerSession, HttpClient httpClient, SseScanSession sseScanSession, Logging logging) {
        this(scannerSession, httpClient, sseScanSession, logging, null);
    }

    SseProxyServer(McpScannerSession scannerSession,
                   HttpClient httpClient,
                   SseScanSession sseScanSession,
                   Logging logging,
                   Supplier<SseScanSession> sseScanSessionFactory) {
        super(LOOPBACK_HOST, 0);
        this.scannerSession = scannerSession;
        this.httpClient = httpClient;
        this.sseScanSession = sseScanSession;
        this.logging = logging;
        this.idRewriter = new JsonRpcIdRewriter(scannerSession::nextRequestId, logging,
                scannerSession.eventLog());
        this.redirectInterceptor = new RedirectLoggingInterceptor(scannerSession.eventLog());
        this.sseScanSessionFactory = sseScanSessionFactory != null
                ? sseScanSessionFactory
                : () -> new SseScanSession(
                        scannerSession.sseUrl(),
                        scannerSession.scannerHeaders(),
                        httpClient,
                        scannerSession::nextRequestId,
                        scannerSession.eventLog(),
                        logging);
    }

    public int port() {
        return getListeningPort();
    }

    @Override
    public Response serve(IHTTPSession session) {
        String endpoint = scannerSession.resolvedEndpoint();
        if (endpoint == null) {
            return newFixedLengthResponse(Response.Status.SERVICE_UNAVAILABLE,
                    "application/json", "{\"error\":\"MCP server not connected\"}");
        }

        if (session.getMethod() != Method.POST) {
            return rejectUnexpectedRequest(session, statusOf(405),
                    "method " + session.getMethod() + " not allowed");
        }
        if (!isExpectedEndpoint(endpoint, session)) {
            return rejectUnexpectedRequest(session, statusOf(404),
                    "request path does not match resolved MCP endpoint");
        }

        try {
            forwardConcurrencyLimiter.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scannerSession.eventLog().warn("Proxy request interrupted while awaiting concurrency slot");
            return newFixedLengthResponse(statusOf(502),
                    "application/json", "{\"error\":\"Request interrupted\"}");
        }
        try {
            Map<String, String> bodyMap = new HashMap<>();
            session.parseBody(bodyMap);
            String rewrittenBody = idRewriter.rewrite(bodyMap.getOrDefault("postData", ""));

            if (scannerSession.transportType() == TransportType.SSE) {
                return serveSse(rewrittenBody, session.getHeaders());
            }

            return serveStreamableHttp(endpoint, rewrittenBody, session.getHeaders());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scannerSession.eventLog().warn("Proxy request interrupted");
            return newFixedLengthResponse(statusOf(502),
                    "application/json", "{\"error\":\"Request interrupted\"}");
        } catch (Exception e) {
            scannerSession.eventLog().warn("Proxy error: " + e.getMessage());
            return newFixedLengthResponse(statusOf(502),
                    "application/json", "{\"error\":\"Proxy error: " + e.getMessage() + "\"}");
        } finally {
            forwardConcurrencyLimiter.release();
        }
    }

    int concurrencyPermitsAvailable() {
        return forwardConcurrencyLimiter.availablePermits();
    }

    @Override
    public void stop() {
        resetScanSession();
        super.stop();
    }

    public synchronized void resetScanSession() {
        closeSseScanSession();
    }

    private Response serveStreamableHttp(String endpoint, String requestBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        ProxyResponse converted = forwardStreamableHttp(endpoint, requestBody, requestHeaders);

        if (isAuthChallenge(converted) && scannerSession.refreshAuth()) {
            scannerSession.eventLog().info("Authentication refresh after 401, retrying");
            logging.logToOutput("Refreshed auth credentials after 401; retrying request");
            converted = forwardStreamableHttp(endpoint, requestBody, requestHeaders);
        } else if (isAuthChallenge(converted)) {
            logging.logToError("Auth refresh failed; returning 401 to Burp");
            scannerSession.eventLog().warn("Auth refresh failed; returning 401 to Burp");
        }

        if (isSessionNotFound(converted) && scannerSession.refreshScannerSession()) {
            logging.logToOutput("Refreshed scanner session after 404; retrying request");
            scannerSession.eventLog().info("Refreshed scanner session after 404, retrying");
            converted = forwardStreamableHttp(endpoint, requestBody, requestHeaders);
        } else if (isSessionNotFound(converted)) {
            logging.logToError("Scanner session refresh failed; returning 404 to Burp");
            scannerSession.eventLog().error("Scanner session refresh failed; returning 404 to Burp");
        }

        String responseBody = converted.body() != null ? converted.body() : "";
        return newFixedLengthResponse(statusOf(converted.statusCode()), converted.contentType(), responseBody);
    }

    private ProxyResponse forwardStreamableHttp(String endpoint, String requestBody,
                                                Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        HttpRequest.Builder forwardBuilder = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .timeout(DEFAULT_RESPONSE_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody));

        applyForwardHeaders(forwardBuilder, requestHeaders);

        HttpResponse<InputStream> response = redirectInterceptor.sendAndLog(
                httpClient, forwardBuilder.build(), HttpResponse.BodyHandlers.ofInputStream());

        String contentType = response.headers().firstValue("Content-Type").orElse("application/json");
        try (InputStream body = response.body()) {
            return convertStreamingResponse(response.statusCode(), contentType, body);
        }
    }

    // Two-layer header merge:
    //   (1) scanner-provided headers (Burp's per-request headers) take precedence; reserved
    //       transport headers and the strip sentinel are filtered out before forwarding.
    //   (2) session-stored headers (Authorization / Mcp-Session-Id / custom auth) are only
    //       injected for header names the scanner did not already supply. When the scanner
    //       sends the strip sentinel, all auth-bearing session headers are suppressed too —
    //       this is how auth-bypass checks signal "the proxy must NOT re-inject session auth".
    private void applyForwardHeaders(HttpRequest.Builder builder, Map<String, String> scannerHeaders) {
        Map<String, String> incoming = scannerHeaders != null ? scannerHeaders : Map.of();
        boolean stripAuth = hasStripAuthSentinel(incoming);

        Set<String> scannerHeaderNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, String> entry : incoming.entrySet()) {
            String name = entry.getKey();
            if (RESERVED_FORWARD_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            if (name.equalsIgnoreCase(ScannerSentinels.STRIP_AUTH_HEADER)) {
                continue;
            }
            builder.header(name, entry.getValue());
            scannerHeaderNames.add(name);
        }

        for (Map.Entry<String, String> entry : scannerSession.scannerHeaders().entrySet()) {
            String name = entry.getKey();
            if (scannerHeaderNames.contains(name)) {
                continue;
            }
            if (stripAuth && isAuthBearing(name)) {
                continue;
            }
            builder.header(name, entry.getValue());
        }
    }

    private static boolean hasStripAuthSentinel(Map<String, String> headers) {
        for (String name : headers.keySet()) {
            if (name.equalsIgnoreCase(ScannerSentinels.STRIP_AUTH_HEADER)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAuthBearing(String headerName) {
        return !NON_AUTH_SESSION_HEADERS.contains(headerName.toLowerCase(Locale.ROOT));
    }

    private static Set<String> caseInsensitiveSet(String... values) {
        TreeSet<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (String value : values) {
            set.add(value);
        }
        return set;
    }

    static ProxyResponse convertStreamingResponse(int statusCode, String contentType, InputStream body) throws IOException {
        if (contentType != null && contentType.contains("text/event-stream")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
            String json = SseResponseParser.extractJsonRpcResponse(reader);
            if (json != null) {
                return new ProxyResponse(statusCode, "application/json", json);
            }
            return new ProxyResponse(statusCode, contentType, "");
        }
        return new ProxyResponse(statusCode, contentType, BoundedBodyReader.readUtf8(body));
    }

    private static boolean isSessionNotFound(ProxyResponse response) {
        return response.statusCode() == 404
                && response.body() != null
                && SESSION_NOT_FOUND_CODE.matcher(response.body()).find();
    }

    private static boolean isAuthChallenge(ProxyResponse response) {
        return HttpAuthResponses.isAuthChallenge(response.statusCode());
    }

    private Response serveSse(String requestBody, Map<String, String> requestHeaders) {
        try {
            ProxyResponse converted = forwardSse(requestBody, requestHeaders);

            if (isAuthChallenge(converted) && scannerSession.refreshAuth()) {
                scannerSession.eventLog().info("Authentication refresh after 401, retrying");
                logging.logToOutput("Refreshed auth credentials after 401; retrying SSE request");
                closeSseScanSession();
                converted = forwardSse(requestBody, requestHeaders);
            } else if (isAuthChallenge(converted)) {
                logging.logToError("Auth refresh failed; returning 401 to Burp (SSE)");
                scannerSession.eventLog().warn("Auth refresh failed; returning 401 to Burp (SSE)");
            }

            String body = converted.body() != null ? converted.body() : "";
            return newFixedLengthResponse(statusOf(converted.statusCode()), converted.contentType(), body);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scannerSession.eventLog().warn("SSE proxy request interrupted");
            return newFixedLengthResponse(statusOf(502),
                    "application/json", "{\"error\":\"Request interrupted\"}");
        } catch (Exception e) {
            scannerSession.eventLog().warn("SSE proxy error: " + e.getMessage());
            return newFixedLengthResponse(statusOf(502),
                    "application/json", "{\"error\":\"SSE proxy error: " + e.getMessage() + "\"}");
        }
    }

    private ProxyResponse forwardSse(String requestBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        SseScanSession session = getOrCreateSseScanSession();
        return session.forwardRequest(requestBody, requestHeaders);
    }

    private synchronized SseScanSession getOrCreateSseScanSession() {
        if (sseScanSession == null) {
            sseScanSession = sseScanSessionFactory.get();
        }
        return sseScanSession;
    }

    private synchronized void closeSseScanSession() {
        if (sseScanSession != null) {
            try {
                sseScanSession.close();
            } catch (IOException e) {
                logging.logToError("Error closing SSE scan session: " + e.getMessage());
                scannerSession.eventLog().warn("Error closing SSE scan session: " + e.getMessage());
            }
            sseScanSession = null;
        }
    }

    private Response rejectUnexpectedRequest(IHTTPSession session, Response.IStatus status, String reason) {
        scannerSession.eventLog().warn("Local proxy rejected request from "
                + session.getRemoteIpAddress() + " " + session.getMethod() + " " + session.getUri()
                + ": " + reason);
        return newFixedLengthResponse(status, "application/json",
                "{\"error\":\"" + reason + "\"}");
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
        // Path-only match, mirroring McpHttpHandler.proxyTarget's path-only routing contract. The
        // query is deliberately ignored: SSE message URLs carry a varying session_id and fuzzed
        // requests vary the query, so requiring a query match would 404 legitimate traffic.
        return Objects.equals(normalizePath(target.getRawPath()), normalizePath(session.getUri()));
    }

    private static String normalizePath(String path) {
        return (path == null || path.isEmpty()) ? "/" : path;
    }

    private static Response.IStatus statusOf(int code) {
        return new Response.IStatus() {
            @Override public String getDescription() { return code + " "; }
            @Override public int getRequestStatus() { return code; }
        };
    }
}
