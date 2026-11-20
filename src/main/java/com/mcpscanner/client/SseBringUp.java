package com.mcpscanner.client;

import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.core.connection.McpConnection;
import com.mcpscanner.core.connection.SseSession;
import com.mcpscanner.core.connection.SseStreamFactory;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpFlow;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

final class SseBringUp {

    private static final Duration SSE_DISCOVERY_TIMEOUT = Duration.ofSeconds(5);

    private final McpFlow flow;
    private final SseEndpointDiscoverer discoverer;
    private final ProtocolHttpExchange exchange;
    private final RedirectPolicy redirectPolicy;
    private final ConnectionAttemptSink sink;
    private final ServerPings serverPings;
    private volatile SseExchangeListener exchangeListener = SseExchangeListener.IGNORING;

    SseBringUp(McpFlow flow, SseEndpointDiscoverer discoverer, ProtocolHttpExchange exchange,
               RedirectPolicy redirectPolicy, ConnectionAttemptSink sink, ServerPings serverPings) {
        this.flow = flow;
        this.discoverer = discoverer;
        this.exchange = exchange;
        this.redirectPolicy = redirectPolicy;
        this.sink = sink;
        this.serverPings = serverPings;
    }

    void observeExchangesWith(SseExchangeListener listener) {
        exchangeListener = Objects.requireNonNull(listener, "listener");
    }

    SseSession open(String target, ConnectionAttempt attempt, RedirectMode redirectMode, ClientProfile profile) {
        return new McpConnection(flow, attempt.credentials()).openSse(
                headers -> openStream(target, headers, attempt, redirectMode), target, profile);
    }

    ProbeSseStream openProbeStream(String target, Map<String, String> headers) {
        SseEndpointDiscoverer.DiscoveryResult discovered = discoverer.discover(
                URI.create(target), headers, SSE_DISCOVERY_TIMEOUT);
        return new ProbeSseStream(discovered.messageUrl(), exchange.replyReader(discovered.sseStream()));
    }

    boolean redirectModeChanged(RedirectMode expected) {
        return expected != redirectPolicy.mode();
    }

    void requireRedirectMode(RedirectMode expected) {
        if (redirectModeChanged(expected)) {
            throw redirectModeChangedFailure();
        }
    }

    static IllegalStateException redirectModeChangedFailure() {
        return new IllegalStateException("Redirect mode changed; Reconnect before using the SSE session");
    }

    private void recordMessageEndpointOrClose(ConnectionAttempt attempt,
                                              SseEndpointDiscoverer.DiscoveryResult discovered) {
        try {
            sink.recordSseMessageEndpoint(attempt, discovered.messageUrl());
        } catch (RuntimeException staleAttempt) {
            ProtocolBodyReader.closeQuietly(discovered.sseStream());
            throw staleAttempt;
        }
    }

    private SseStreamFactory.Stream openStream(String target, Map<String, String> headers,
                                               ConnectionAttempt attempt, RedirectMode redirectMode) {
        SseEndpointDiscoverer.DiscoveryResult discovered = discoverer.discover(
                URI.create(target), headers, SSE_DISCOVERY_TIMEOUT);
        URI messageUrl = discovered.messageUrl();
        recordMessageEndpointOrClose(attempt, discovered);
        return new DiscoveredSseStream(messageUrl, exchange.replyReader(discovered.sseStream()),
                json -> sink.recordSseAdmission(attempt, json), serverPings, discovered.opening(), exchangeListener,
                request -> {
                    requireRedirectMode(redirectMode);
                    sink.rememberCredentials(attempt, request.headers());
                    return exchange.recordedPost(messageUrl, request);
                });
    }
}
