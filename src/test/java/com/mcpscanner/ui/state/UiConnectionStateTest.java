package com.mcpscanner.ui.state;

import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.client.TransportType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UiConnectionStateTest {

    @Test
    void disconnectedStatusReportsDisconnected() {
        ConnectionStatus status = UiConnectionState.disconnected().status();

        assertThat(status.state()).isEqualTo(ConnectionState.DISCONNECTED);
        assertThat(status.primaryButtonLabel()).isEqualTo("Connect");
    }

    @Test
    void connectingStatusReportsProgressMessageAndCancelLabel() {
        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                "https://mcp.example.com/mcp", TransportType.STREAMABLE_HTTP, "mcp.example.com",
                "None", null);
        UiConnectionState state = UiConnectionState.connecting(
                attempt, Cancellable.NOOP, ConnectPhase.OAUTH, "OAuth: opening browser…");

        ConnectionStatus status = state.status();

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTING);
        assertThat(status.message()).isEqualTo("OAuth: opening browser…");
        assertThat(status.primaryButtonLabel()).isEqualTo("Cancel");
    }

    @Test
    void connectedStatusFormatsHostAndToolCount() {
        ConnectResult result = sampleResult(3);
        UiConnectionState state = UiConnectionState.connected(result, "mcp.example.com",
                ConnectionStatus.connected(null, "mcp.example.com", null, 3));

        ConnectionStatus status = state.status();

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(status.message()).isEqualTo("Connected to mcp.example.com · 3 tools");
        assertThat(status.primaryButtonLabel()).isEqualTo("Disconnect");
    }

    @Test
    void failedStatusReportsPhaseAndReason() {
        ConnectionStatus status = UiConnectionState.failed(ConnectPhase.OAUTH, "scope rejected").status();

        assertThat(status.state()).isEqualTo(ConnectionState.FAILED);
        assertThat(status.message()).isEqualTo("OAuth failed: scope rejected");
        assertThat(status.primaryButtonLabel()).isEqualTo("Connect");
    }

    @Test
    void connectingExposesAttemptAndCancellable() {
        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                "https://mcp.example.com/mcp", TransportType.SSE, "mcp.example.com",
                "None", null);
        Cancellable cancellable = () -> { /* no-op */ };

        UiConnectionState.Connecting state = (UiConnectionState.Connecting) UiConnectionState.connecting(
                attempt, cancellable, ConnectPhase.CONNECT, "Connecting…");

        assertThat(state.attempt()).isSameAs(attempt);
        assertThat(state.cancellable()).isSameAs(cancellable);
        assertThat(state.phase()).isEqualTo(ConnectPhase.CONNECT);
    }

    @Test
    void connectingWithCancellableReplacesTheHandleButKeepsOtherFields() {
        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                "https://mcp.example.com/mcp", TransportType.STREAMABLE_HTTP, "mcp.example.com",
                "None", null);
        UiConnectionState.Connecting initial = (UiConnectionState.Connecting) UiConnectionState.connecting(
                attempt, Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        Cancellable replacement = () -> { /* no-op */ };
        UiConnectionState.Connecting updated = initial.withCancellable(replacement);

        assertThat(updated.cancellable()).isSameAs(replacement);
        assertThat(updated.attempt()).isSameAs(attempt);
        assertThat(updated.phase()).isEqualTo(ConnectPhase.CONNECT);
        assertThat(updated.status().message()).isEqualTo("Connecting…");
    }

    @Test
    void connectedExposesResult() {
        ConnectResult result = sampleResult(7);
        UiConnectionState.Connected state = (UiConnectionState.Connected) UiConnectionState.connected(
                result, "mcp.example.com", ConnectionStatus.connected(null, "mcp.example.com", null, 7));

        assertThat(state.result()).isSameAs(result);
        assertThat(state.host()).isEqualTo("mcp.example.com");
    }

    private static ConnectResult sampleResult(int toolCount) {
        List<McpToolDefinition> tools = new java.util.ArrayList<>();
        for (int i = 0; i < toolCount; i++) {
            tools.add(new McpToolDefinition("tool" + i, "desc", "{}"));
        }
        return new ConnectResult(
                tools,
                List.<McpResourceDefinition>of(),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());
    }
}
