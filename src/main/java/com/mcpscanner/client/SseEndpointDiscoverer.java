package com.mcpscanner.client;

import com.mcpscanner.logging.FailureDescription;
import com.mcpscanner.logging.LogRedaction;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.HttpOrigin;
import com.mcpscanner.mcp.SseFrameReader;
import com.mcpscanner.core.protocol.McpSse;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.connection.SseOpenException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public final class SseEndpointDiscoverer {

    private static final int MAX_ENDPOINT_EVENT_BYTES = 64 * 1024;
    private static final int MAX_ENDPOINT_EVENTS = 32;
    private static final long RESPONSE_GRACE_MILLIS = 500;
    private static final SseFrameReader.Limits ENDPOINT_EVENT_LIMITS = SseFrameReader.Limits.perFrame(
            MAX_ENDPOINT_EVENT_BYTES, "SSE endpoint event exceeded response bound");

    public record DiscoveryResult(URI messageUrl, InputStream sseStream, SseStreamOpening opening) {}

    // SSE keeps JDK HttpClient: api.http() is synchronous and cannot consume an open
    // text/event-stream; Montoya exposes no proxy-listener endpoint.
    private final HttpClient httpClient;
    private final McpEventLog eventLog;
    private final RedirectLoggingInterceptor redirectInterceptor;

    public SseEndpointDiscoverer(HttpClient httpClient, McpEventLog eventLog) {
        this(httpClient, eventLog, new RedirectLoggingInterceptor(eventLog));
    }

    public SseEndpointDiscoverer(HttpClient httpClient, McpEventLog eventLog,
                                 RedirectLoggingInterceptor redirectInterceptor) {
        this.httpClient = httpClient;
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
        this.redirectInterceptor = Objects.requireNonNull(redirectInterceptor, "redirectInterceptor");
    }

    public DiscoveryResult discover(URI sseEndpoint, Map<String, String> authHeaders, Duration timeout) {
        CompletableFuture<HttpResponse<InputStream>> request = redirectInterceptor.sendAsyncAndLog(
                httpClient, buildRequest(sseEndpoint, authHeaders, timeout), HttpResponse.BodyHandlers.ofInputStream());
        try {
            HttpResponse<InputStream> response = request.get(
                    timeout.toMillis() + RESPONSE_GRACE_MILLIS, TimeUnit.MILLISECONDS);
            rejectAuthChallenge(response);
            return awaitEndpointEvent(sseEndpoint, response, timeout);
        } catch (SseOpenException challenge) {
            throw challenge;
        } catch (Exception failure) {
            throw discoveryFailure(failure, request);
        }
    }

    private static void rejectAuthChallenge(HttpResponse<InputStream> response) {
        if (!HttpAuthResponses.isAuthChallenge(response.statusCode())) {
            return;
        }
        closeQuietly(response.body());
        throw new SseOpenException(new McpFlow.HttpResponse(
                response.statusCode(), joinedHeaders(response), "", true));
    }

    private static Map<String, String> joinedHeaders(HttpResponse<InputStream> response) {
        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) headers.put(name, String.join(", ", values));
        });
        return headers;
    }

    private DiscoveryResult awaitEndpointEvent(URI sseEndpoint, HttpResponse<InputStream> response,
                                               Duration timeout) throws Exception {
        CompletableFuture<DiscoveryResult> endpointEvent = CompletableFuture.supplyAsync(
                () -> resolveDiscoveredEndpoint(sseEndpoint, response));
        try {
            return endpointEvent.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            endpointEvent.cancel(true);
            closeQuietly(response.body());
            throw e;
        }
    }

    private RuntimeException discoveryFailure(Exception failure, Future<?> request) {
        if (failure instanceof InterruptedException) {
            request.cancel(true);
            Thread.currentThread().interrupt();
            return new IllegalStateException("SSE endpoint discovery interrupted", failure);
        }
        if (failure instanceof IllegalStateException stateFailure) {
            eventLog.warn(stateFailure.getMessage());
            return stateFailure;
        }
        if (failure instanceof ExecutionException execution) {
            return endpointResolutionFailure(execution.getCause());
        }
        request.cancel(true);
        eventLog.warn("SSE endpoint discovery failed: " + FailureDescription.of(failure));
        return new IllegalStateException("SSE endpoint discovery failed", failure);
    }

    private RuntimeException endpointResolutionFailure(Throwable cause) {
        eventLog.warn("SSE endpoint discovery failed: " + FailureDescription.of(cause));
        if (cause instanceof IllegalStateException failure) {
            return failure;
        }
        return new IllegalStateException("SSE endpoint discovery failed", cause);
    }

    private DiscoveryResult resolveDiscoveredEndpoint(URI sseEndpoint, HttpResponse<InputStream> response) {
        InputStream body = response.body();
        try {
            if (response.statusCode() < 200 || response.statusCode() >= 300 || body == null) {
                throw new SseStreamRejectedException("SSE stream was not established");
            }
            URI reachedEndpoint = response.uri() != null ? response.uri() : sseEndpoint;
            return readEndpointEvent(reachedEndpoint, body, new SseStreamOpening(response));
        } catch (IOException | IllegalArgumentException e) {
            closeQuietly(body);
            throw new IllegalStateException("SSE endpoint discovery failed: " + e.getMessage(), e);
        }
    }

    private DiscoveryResult readEndpointEvent(URI reachedEndpoint, InputStream body, SseStreamOpening opening)
            throws IOException {
        SseFrameReader events = SseFrameReader.over(body, ENDPOINT_EVENT_LIMITS);
        for (int i = 0; i < MAX_ENDPOINT_EVENTS; i++) {
            String event = events.nextFrame();
            if (event == null) {
                throw new SseStreamRejectedException("SSE stream closed before endpoint event");
            }
            if (McpSse.isEndpoint(event, MAX_ENDPOINT_EVENT_BYTES)) {
                return new DiscoveryResult(sameOriginEndpoint(reachedEndpoint, event), events.remainder(body),
                        opening);
            }
        }
        return fallback(reachedEndpoint, events.remainder(body), opening);
    }

    private static URI sameOriginEndpoint(URI reachedEndpoint, String event) throws IOException {
        URI resolved = reachedEndpoint.resolve(McpSse.endpoint(
                reachedEndpoint.toString(), event, MAX_ENDPOINT_EVENT_BYTES));
        if (!HttpOrigin.sameOrigin(reachedEndpoint, resolved)) {
            throw new SseStreamRejectedException("Cross-origin SSE endpoint rejected: " + LogRedaction.redactQuery(resolved.toString()));
        }
        return resolved;
    }

    private DiscoveryResult fallback(URI sseEndpoint, InputStream liveStream, SseStreamOpening opening) {
        String path = sseEndpoint.getPath();
        String messagePath = path.endsWith("/sse")
                ? path.substring(0, path.length() - 3) + "message"
                : path.endsWith("/") ? path + "message" : path + "/message";
        try {
            URI messageUrl = new URI(sseEndpoint.getScheme(), sseEndpoint.getUserInfo(),
                    sseEndpoint.getHost(), sseEndpoint.getPort(), messagePath, sseEndpoint.getQuery(), null);
            eventLog.info("Using fallback SSE message endpoint: " + LogRedaction.redactQuery(messageUrl.toString()));
            return new DiscoveryResult(messageUrl, liveStream, opening);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid SSE fallback URL", e);
        }
    }

    private static HttpRequest buildRequest(URI sseEndpoint, Map<String, String> authHeaders, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(sseEndpoint)
                .timeout(timeout)
                .GET();
        authHeaders.forEach(builder::header);
        return builder.build();
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
