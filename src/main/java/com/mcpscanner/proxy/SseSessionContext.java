package com.mcpscanner.proxy;

import com.mcpscanner.mcp.LegacySseRoutes;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.core.protocol.ClientProfile;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

record SseSessionContext(HttpClient httpClient,
                         LongSupplier requestIds,
                         Supplier<ClientProfile> clientProfile,
                         McpEventLog eventLog,
                         RedirectLoggingInterceptor redirects,
                         LongSupplier pendingResponseBudget,
                         Duration responseTimeout,
                         Duration handshakeTimeout,
                         ServerPings serverPings,
                         UpstreamCaptures captures,
                         LegacySseRoutes legacySseRoutes,
                         MalformedRequestWaits malformedRequestWaits) {

    static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofSeconds(30);
    static final Duration DEFAULT_HANDSHAKE_TIMEOUT = Duration.ofSeconds(5);

    SseSessionContext {
        Objects.requireNonNull(httpClient, "httpClient");
        Objects.requireNonNull(requestIds, "requestIds");
        Objects.requireNonNull(clientProfile, "clientProfile");
        Objects.requireNonNull(eventLog, "eventLog");
        Objects.requireNonNull(redirects, "redirects");
        Objects.requireNonNull(pendingResponseBudget, "pendingResponseBudget");
        Objects.requireNonNull(responseTimeout, "responseTimeout");
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
        Objects.requireNonNull(serverPings, "serverPings");
        Objects.requireNonNull(captures, "captures");
        Objects.requireNonNull(legacySseRoutes, "legacySseRoutes");
        Objects.requireNonNull(malformedRequestWaits, "malformedRequestWaits");
    }
}
