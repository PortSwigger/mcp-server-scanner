package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.SseResponseParser;

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
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public final class SseEndpointDiscoverer {

    public record DiscoveryResult(URI messageUrl, InputStream sseStream) {}

    // SSE keeps JDK HttpClient: api.http() is synchronous and cannot consume an open
    // text/event-stream; Montoya exposes no proxy-listener endpoint.
    private final HttpClient httpClient;
    private final Logging logging;
    private final McpEventLog eventLog;

    public SseEndpointDiscoverer(HttpClient httpClient, Logging logging) {
        this(httpClient, logging, McpEventLog.noop());
    }

    public SseEndpointDiscoverer(HttpClient httpClient, Logging logging, McpEventLog eventLog) {
        this.httpClient = httpClient;
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    public DiscoveryResult discover(URI sseEndpoint, Map<String, String> authHeaders, Duration timeout) {
        HttpRequest request = buildRequest(sseEndpoint, authHeaders, timeout);
        CompletableFuture<HttpResponse<InputStream>> future =
                httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
        try {
            HttpResponse<InputStream> response = future.get(
                    timeout.toMillis() + 500, TimeUnit.MILLISECONDS);
            return resolveDiscoveredEndpoint(sseEndpoint, response);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return fallback(sseEndpoint);
        } catch (Exception e) {
            future.cancel(true);
            logging.logToError("Failed to discover SSE message endpoint: " + e.getClass().getSimpleName());
            eventLog.warn("SSE endpoint discovery failed: " + e.getClass().getSimpleName());
            return fallback(sseEndpoint);
        }
    }

    private DiscoveryResult resolveDiscoveredEndpoint(URI sseEndpoint, HttpResponse<InputStream> response) {
        InputStream body = response.body();
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
            String discoveredPath = SseResponseParser.extractEndpointUrl(reader);
            if (discoveredPath == null) {
                closeQuietly(body);
                return fallback(sseEndpoint);
            }
            String resolved = SseResponseParser.resolveMessageUrl(sseEndpoint.toString(), discoveredPath);
            if (!sameHost(sseEndpoint, URI.create(resolved))) {
                closeQuietly(body);
                logging.logToError("Rejecting cross-host SSE endpoint: " + redactQueryString(resolved));
                eventLog.warn("Rejecting cross-host SSE endpoint: " + redactQueryString(resolved));
                return fallback(sseEndpoint);
            }
            return new DiscoveryResult(URI.create(resolved), body);
        } catch (IOException | IllegalArgumentException e) {
            closeQuietly(body);
            return fallback(sseEndpoint);
        }
    }

    private DiscoveryResult fallback(URI sseEndpoint) {
        String fallbackUrl = sseEndpoint.toString().replaceAll("/sse$", "") + "/message";
        logging.logToOutput("Using fallback SSE message endpoint: " + fallbackUrl);
        eventLog.info("Using fallback SSE message endpoint: " + fallbackUrl);
        return new DiscoveryResult(URI.create(fallbackUrl), null);
    }

    private static HttpRequest buildRequest(URI sseEndpoint, Map<String, String> authHeaders, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(sseEndpoint)
                .timeout(timeout)
                .GET();
        authHeaders.forEach(builder::header);
        return builder.build();
    }

    private static boolean sameHost(URI a, URI b) {
        return a.getHost() != null && a.getHost().equalsIgnoreCase(b.getHost());
    }

    private static String redactQueryString(String url) {
        if (url == null) {
            return null;
        }
        int q = url.indexOf('?');
        return q < 0 ? url : url.substring(0, q) + "?<redacted>";
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
