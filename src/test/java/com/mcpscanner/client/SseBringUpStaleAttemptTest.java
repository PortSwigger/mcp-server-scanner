package com.mcpscanner.client;

import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.core.protocol.McpFlow;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SseBringUpStaleAttemptTest {

    private static final String TARGET = "http://mcp.example/sse";

    @Test
    void closesTheDiscoveredStreamWhenTheAttemptWentStale() {
        AtomicBoolean closed = new AtomicBoolean();
        SseEndpointDiscoverer discoverer = mock(SseEndpointDiscoverer.class);
        when(discoverer.discover(any(), any(), any(Duration.class))).thenReturn(new SseEndpointDiscoverer.DiscoveryResult(
                URI.create("http://mcp.example/message"), trackedStream(closed),
                new SseStreamOpening(mock(java.net.http.HttpResponse.class))));
        ConnectionAttemptSink sink = mock(ConnectionAttemptSink.class);
        doThrow(new IllegalStateException("stale")).when(sink).recordSseMessageEndpoint(any(), any());
        SseBringUp bringUp = new SseBringUp(new McpFlow(BoundedBodyReader.MAX_RESPONSE_BYTES, 32), discoverer,
                mock(ProtocolHttpExchange.class), mock(RedirectPolicy.class), sink, new ServerPings(() -> false));

        assertThatThrownBy(() -> bringUp.open(TARGET, attempt(), RedirectMode.METHOD_PRESERVING_SAME_ORIGIN,
                ClientIdentityProvider.defaults().current().profile()))
                .hasStackTraceContaining("stale");
        assertThat(closed).isTrue();
    }

    private static ConnectionAttempt attempt() {
        return new ConnectionAttempt(1, new GuardedCredentials(new ScannerCredentials(new NoAuthStrategy(), () -> false)));
    }

    private static ByteArrayInputStream trackedStream(AtomicBoolean closed) {
        return new ByteArrayInputStream(new byte[0]) {
            @Override
            public void close() {
                closed.set(true);
            }
        };
    }
}
