package com.mcpscanner.proxy;

import com.mcpscanner.client.ConnectionLossWatch;
import com.mcpscanner.client.JdkProtocolHttpTransport;
import com.mcpscanner.client.McpHttpClients;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.ResendableRequests;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

public final class TestSseProxies {

    private TestSseProxies() {}

    public static Builder builder(McpScannerSession session) {
        return new Builder(session);
    }

    public static final class Builder {
        private final McpScannerSession session;
        private final Queue<SseScanSession> managedSessions = new ArrayDeque<>();
        private HttpClient httpClient;
        private ProtocolHttpTransport upstreamTransport;
        private Duration responseTimeout = ProxySettings.DEFAULT_RESPONSE_TIMEOUT;
        private ClientIdentityProvider identityProvider = ClientIdentityProvider.defaults();
        private Supplier<RedirectMode> redirectMode = () -> RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        private LongSupplier postBodyLimit = ResourceCap.PROXY_POST_BODY_BYTES::defaultValue;
        private LongSupplier pendingResponseBudget = ResourceCap.SSE_PENDING_RESPONSE_BYTES::defaultValue;
        private BooleanSupplier answerServerPings = () -> true;
        private ToolCallReplyObserver toolCallReplies = ToolCallReplyObserver.NONE;
        private UpstreamRecording recording = UpstreamRecording.create();
        private McpOperationFraming.Framer operationFramer;
        private ResendableRequests resendableRequests = new ResendableRequests();
        private ConnectionLossWatch connectionLossWatch = ConnectionLossWatch.disabled();

        private Builder(McpScannerSession session) {
            this.session = session;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder upstreamTransport(ProtocolHttpTransport upstreamTransport) {
            this.upstreamTransport = upstreamTransport;
            return this;
        }

        public Builder responseTimeout(Duration responseTimeout) {
            this.responseTimeout = responseTimeout;
            return this;
        }

        public Builder identityProvider(ClientIdentityProvider identityProvider) {
            this.identityProvider = identityProvider;
            return this;
        }

        public Builder redirectMode(Supplier<RedirectMode> redirectMode) {
            this.redirectMode = redirectMode;
            return this;
        }

        public Builder postBodyLimit(long limitBytes) {
            this.postBodyLimit = () -> limitBytes;
            return this;
        }

        public Builder answerServerPings(BooleanSupplier answerServerPings) {
            this.answerServerPings = answerServerPings;
            return this;
        }

        public Builder toolCallReplies(ToolCallReplyObserver toolCallReplies) {
            this.toolCallReplies = toolCallReplies;
            return this;
        }

        public Builder recording(UpstreamRecording recording) {
            this.recording = recording;
            return this;
        }

        public Builder operationFramer(McpOperationFraming.Framer operationFramer) {
            this.operationFramer = operationFramer;
            return this;
        }

        public Builder resendableRequests(ResendableRequests resendableRequests) {
            this.resendableRequests = resendableRequests;
            return this;
        }

        public Builder connectionLossWatch(ConnectionLossWatch connectionLossWatch) {
            this.connectionLossWatch = connectionLossWatch;
            return this;
        }

        Builder managedSessions(SseScanSession... sessions) {
            managedSessions.addAll(List.of(sessions));
            return this;
        }

        public SseProxyServer build() {
            HttpClient client = httpClient != null ? httpClient : McpHttpClients.upstream();
            ProtocolHttpTransport transport = recording.captures().recording(upstreamTransport != null
                    ? upstreamTransport : new JdkProtocolHttpTransport(client));
            ProxySettings settings = new ProxySettings(client, transport, responseTimeout, identityProvider,
                    redirectMode, postBodyLimit, pendingResponseBudget, answerServerPings);
            return new SseProxyServer(session, settings, this::nextManagedSession, toolCallReplies, recording,
                    operationFramer != null ? operationFramer : session, resendableRequests, connectionLossWatch);
        }

        private SseScanSession nextManagedSession(String sseUrl, java.util.Map<String, String> headers,
                                                  SseSessionContext context) {
            SseScanSession scripted = managedSessions.poll();
            return scripted != null ? scripted : new SseScanSession(sseUrl, headers, context);
        }
    }
}
