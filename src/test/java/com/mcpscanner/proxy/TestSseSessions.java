package com.mcpscanner.proxy;

import com.mcpscanner.mcp.LegacySseRoutes;
import com.mcpscanner.mcp.ServerPings;

import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.config.ClientIdentity;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.core.protocol.ClientProfile;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class TestSseSessions {

    private TestSseSessions() {}

    static Builder builder(String sseUrl, HttpClient httpClient) {
        return new Builder(sseUrl, httpClient);
    }

    static final class Builder {
        private final String sseUrl;
        private final HttpClient httpClient;
        private Map<String, String> headers = Map.of();
        private LongSupplier requestIds = () -> 1L;
        private Supplier<ClientProfile> clientProfile = () -> ClientIdentity.defaults().profile();
        private McpEventLog eventLog = McpEventLog.noop();
        private Supplier<RedirectMode> redirectMode = () -> RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        private LongSupplier pendingResponseBudget = ResourceCap.SSE_PENDING_RESPONSE_BYTES::defaultValue;
        private Duration responseTimeout = SseSessionContext.DEFAULT_RESPONSE_TIMEOUT;
        private Duration handshakeTimeout = SseSessionContext.DEFAULT_HANDSHAKE_TIMEOUT;
        private MalformedRequestWaits malformedRequestWaits =
                new MalformedRequestWaits(MalformedRequestWaits.DEFAULT_SHORT_WAIT);

        private Builder(String sseUrl, HttpClient httpClient) {
            this.sseUrl = sseUrl;
            this.httpClient = httpClient;
        }

        Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        Builder requestIds(LongSupplier requestIds) {
            this.requestIds = requestIds;
            return this;
        }

        Builder clientProfile(Supplier<ClientProfile> clientProfile) {
            this.clientProfile = clientProfile;
            return this;
        }

        Builder eventLog(McpEventLog eventLog) {
            this.eventLog = eventLog;
            return this;
        }

        Builder redirectMode(Supplier<RedirectMode> redirectMode) {
            this.redirectMode = redirectMode;
            return this;
        }

        Builder pendingResponseBudget(LongSupplier pendingResponseBudget) {
            this.pendingResponseBudget = pendingResponseBudget;
            return this;
        }

        Builder timeouts(Duration responseTimeout, Duration handshakeTimeout) {
            this.responseTimeout = responseTimeout;
            this.handshakeTimeout = handshakeTimeout;
            return this;
        }

        Builder malformedRequestWaits(MalformedRequestWaits malformedRequestWaits) {
            this.malformedRequestWaits = malformedRequestWaits;
            return this;
        }

        SseScanSession build() {
            SseSessionContext context = new SseSessionContext(httpClient, requestIds, clientProfile, eventLog,
                    new RedirectLoggingInterceptor(eventLog, redirectMode), pendingResponseBudget,
                    responseTimeout, handshakeTimeout, new ServerPings(() -> true), new UpstreamCaptures(),
                    new LegacySseRoutes(), malformedRequestWaits);
            return new SseScanSession(sseUrl, headers, context);
        }
    }
}
