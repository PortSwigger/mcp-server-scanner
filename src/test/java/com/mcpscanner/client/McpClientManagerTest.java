package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedProtocolTransport;
import com.mcpscanner.core.protocol.McpResponses.Reply;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.when;

class McpClientManagerTest {
    private final Logging logging = mock(Logging.class);
    private final McpScannerSession session = mock(McpScannerSession.class);
    private final McpServerConfig config = new McpServerConfig("https://example.test/mcp", TransportType.MODERN_HTTP, new NoAuthStrategy());
    private final McpClientManager manager = new McpClientManager(McpEventLog.noop(), session);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(session.resolvedEndpoint()).thenReturn("https://example.test/mcp");
    }

    @Test
    void connects_discovers_and_disconnects() {
        when(session.catalog("tools/list", null)).thenReturn(new Reply(2, Map.of("tools", List.of(Map.of("name", "read", "inputSchema", Map.of("type", "object")))), Map.of()));
        optionalCatalogsEmpty();
        when(session.admissionEnvelope()).thenReturn(Map.of("result", Map.of("serverInfo", Map.of("name", "server"))));
        AtomicInteger disconnects = new AtomicInteger();
        manager.addDisconnectListener(disconnects::incrementAndGet);

        ConnectResult result = manager.connect(config);

        assertThat(manager.isConnected()).isTrue();
        assertThat(result.tools()).hasSize(1);
        assertThat(result.serverMetadata().serverInfo()).containsEntry("name", "server");
        manager.disconnect();
        assertThat(manager.isConnected()).isFalse();
        assertThat(disconnects.get()).isEqualTo(1);
        verify(session, atLeastOnce()).disconnect();
    }

    @Test
    void connectionLostTellsLossListenersBeforeDisconnectingTheConnection() {
        when(session.catalog("tools/list", null)).thenReturn(new Reply(2, Map.of("tools", List.of()), Map.of()));
        optionalCatalogsEmpty();
        when(session.admissionEnvelope()).thenReturn(Map.of("result", Map.of()));
        List<String> order = new java.util.ArrayList<>();
        manager.addConnectionLostListener(() -> order.add("lost:" + manager.isConnected()));
        manager.addDisconnectListener(() -> order.add("disconnected"));
        manager.connect(config);

        manager.connectionLost();

        assertThat(order).containsExactly("lost:true", "disconnected");
        assertThat(manager.isConnected()).isFalse();
    }

    @Test
    void connectionLostWhileNotConnectedDoesNothing() {
        AtomicInteger losses = new AtomicInteger();
        manager.addConnectionLostListener(losses::incrementAndGet);

        manager.connectionLost();

        assertThat(losses.get()).isZero();
    }

    @Test
    void failed_required_catalog_rolls_back_connection() {
        when(session.catalog("tools/list", null)).thenThrow(new IllegalStateException("catalog unavailable"));
        assertThatThrownBy(() -> manager.connect(config)).isInstanceOf(IllegalStateException.class);
        assertThat(manager.isConnected()).isFalse();
        verify(session, atLeastOnce()).disconnect();
    }

    @Test
    void tells_known_tools_listeners_each_tools_page_before_the_rest_of_the_catalog_is_listed() {
        when(session.catalog("tools/list", null)).thenReturn(new Reply(2, Map.of("tools",
                List.of(Map.of("name", "read", "inputSchema", Map.of("type", "object"))), "nextCursor", "p2"), Map.of()));
        when(session.catalog("tools/list", "p2")).thenReturn(new Reply(3, Map.of("tools",
                List.of(Map.of("name", "write", "inputSchema", Map.of("type", "object")))), Map.of()));
        optionalCatalogsEmpty();
        when(session.admissionEnvelope()).thenReturn(Map.of("result", Map.of()));
        List<List<String>> known = new java.util.ArrayList<>();
        manager.addKnownToolsListener(tools -> {
            verify(session, never()).catalog(eq("resources/list"), any());
            known.add(tools.stream().map(com.mcpscanner.mcp.McpToolDefinition::name).toList());
        });

        manager.connect(config);

        assertThat(known).containsExactly(List.of("read"), List.of("read", "write"));
    }

    @Test
    void a_failed_connect_leaves_no_known_tools() {
        when(session.catalog("tools/list", null)).thenReturn(new Reply(2, Map.of("tools",
                List.of(Map.of("name", "read", "inputSchema", Map.of("type", "object"))), "nextCursor", "p2"), Map.of()));
        when(session.catalog("tools/list", "p2")).thenThrow(new IllegalStateException("page unavailable"));
        List<List<?>> known = new java.util.ArrayList<>();
        manager.addKnownToolsListener(known::add);

        assertThatThrownBy(() -> manager.connect(config)).isInstanceOf(IllegalStateException.class);

        assertThat(known).last().asList().isEmpty();
    }

    @Test
    void sse_message_endpoint_session_id_is_redacted_in_the_event_log() {
        McpEventLog eventLog = new McpEventLog(logging);
        McpClientManager sseManager = new McpClientManager(eventLog, session);
        when(session.resolvedEndpoint()).thenReturn("https://example.test/message?session_id=secret-session");
        when(session.catalog("tools/list", null)).thenReturn(new Reply(2, Map.of("tools", List.of()), Map.of()));
        optionalCatalogsEmpty();
        when(session.admissionEnvelope()).thenReturn(Map.of("result", Map.of()));

        sseManager.connect(new McpServerConfig("https://example.test/sse?token=configured-secret",
                TransportType.SSE, new NoAuthStrategy()));

        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .contains("SSE message endpoint: https://example.test/message?<redacted>")
                .noneMatch(message -> message.contains("secret-session") || message.contains("configured-secret"));
    }

    @Test
    void connect_traffic_goes_through_the_injected_protocol_transport() {
        ScriptedProtocolTransport transport = ScriptedProtocolTransport.fakeServer();
        McpClientManager routed = new McpClientManager(McpEventLog.noop(),
                ClientIdentityProvider.defaults(), transport);

        routed.connect(config);

        assertThat(routed.isConnected()).isTrue();
        assertThat(transport.requests()).isNotEmpty()
                .allMatch(request -> request.uri().equals(URI.create("https://example.test/mcp")));
        routed.disconnect();
    }

    private void optionalCatalogsEmpty() {
        when(session.catalog("resources/list", null)).thenReturn(new Reply(3, Map.of("resources", List.of()), Map.of()));
        when(session.catalog("resources/templates/list", null)).thenReturn(new Reply(4, Map.of("resourceTemplates", List.of()), Map.of()));
        when(session.catalog("prompts/list", null)).thenReturn(new Reply(5, Map.of("prompts", List.of()), Map.of()));
    }
}
