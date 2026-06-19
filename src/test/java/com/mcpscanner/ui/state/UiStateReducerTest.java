package com.mcpscanner.ui.state;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.client.TransportType;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class UiStateReducerTest {

    private final UiStateReducer reducer = new UiStateReducer();

    @Test
    void connectRequestedFromDisconnectedProducesConnectingWithSpawnSideEffect() {
        ConnectAttempt attempt = sampleAttempt();

        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectRequested(attempt));

        assertThat(result.state()).isInstanceOf(UiConnectionState.Connecting.class);
        UiConnectionState.Connecting connecting = (UiConnectionState.Connecting) result.state();
        assertThat(connecting.attempt()).isSameAs(attempt);
        assertThat(connecting.cancellable()).isSameAs(Cancellable.NOOP);
        assertThat(connecting.phase()).isEqualTo(ConnectPhase.CONNECT);
        assertThat(result.sideEffects())
                .containsExactly(new UiSideEffect.SpawnConnectWorker(attempt));
    }

    @Test
    void connectRequestedFromFailedProducesConnectingWithSpawnSideEffect() {
        ConnectAttempt attempt = sampleAttempt();

        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.failed(ConnectPhase.CONNECT, "boom"),
                new UiAction.ConnectRequested(attempt));

        assertThat(result.state()).isInstanceOf(UiConnectionState.Connecting.class);
        assertThat(result.sideEffects())
                .containsExactly(new UiSideEffect.SpawnConnectWorker(attempt));
    }

    @Test
    void connectRequestedFromConnectingIsIgnoredAndLogsWarning() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting,
                new UiAction.ConnectRequested(sampleAttempt()));

        assertThat(result.state()).isSameAs(connecting);
        assertThat(result.sideEffects()).hasSize(1);
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void connectRejectedFromDisconnectedTransitionsToFailedWithoutSpawningWorker() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectRejected(ConnectPhase.OAUTH, "scope list cannot be empty"));

        assertThat(result.state()).isEqualTo(
                UiConnectionState.failed(ConnectPhase.OAUTH, "scope list cannot be empty"));
        assertThat(result.sideEffects()).isEmpty();
    }

    @Test
    void connectRejectedFromConnectingIsIgnoredAndLogsWarning() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, new UiAction.ConnectRejected(ConnectPhase.OAUTH, "bad"));

        assertThat(result.state()).isSameAs(connecting);
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void connectWorkerAttachedRecordsCancellableOnConnecting() {
        Cancellable cancellable = () -> { };
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, new UiAction.ConnectWorkerAttached(cancellable));

        assertThat(result.state()).isInstanceOf(UiConnectionState.Connecting.class);
        assertThat(((UiConnectionState.Connecting) result.state()).cancellable()).isSameAs(cancellable);
        assertThat(result.sideEffects()).isEmpty();
    }

    @Test
    void connectWorkerAttachedFromDisconnectedIsIgnored() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectWorkerAttached(() -> { }));

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void connectProgressUpdatesPhaseAndMessageOnConnecting() {
        ConnectAttempt attempt = sampleAttempt();
        UiConnectionState connecting = UiConnectionState.connecting(
                attempt, Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, new UiAction.ConnectProgress(ConnectPhase.OAUTH, "OAuth: opening browser…"));

        UiConnectionState.Connecting updated = (UiConnectionState.Connecting) result.state();
        assertThat(updated.phase()).isEqualTo(ConnectPhase.OAUTH);
        assertThat(updated.message()).isEqualTo("OAuth: opening browser…");
        assertThat(updated.attempt()).isSameAs(attempt);
        assertThat(result.sideEffects()).isEmpty();
    }

    @Test
    void connectProgressFromDisconnectedIsIgnored() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectProgress(ConnectPhase.OAUTH, "anything"));

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void connectSucceededFromConnectingTransitionsToConnectedPopulatesInventoryAndPublishesOauth() {
        ConnectResult result = sampleResult(3);
        OAuthAuthCodeStrategy oauthStrategy = Mockito.mock(OAuthAuthCodeStrategy.class);
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.OAUTH, "OAuth: opening browser…");
        ConnectionStatus connectedStatus = ConnectionStatus.connected(
                "user", "mcp.example.com", null, 3);

        UiStateReducer.Reduction reduction = reducer.reduce(
                connecting,
                new UiAction.ConnectSucceeded(result, "mcp.example.com", connectedStatus, oauthStrategy));

        UiConnectionState.Connected connected = (UiConnectionState.Connected) reduction.state();
        assertThat(connected.result()).isSameAs(result);
        assertThat(connected.host()).isEqualTo("mcp.example.com");
        assertThat(connected.status()).isEqualTo(connectedStatus);
        assertThat(reduction.sideEffects()).containsExactly(
                new UiSideEffect.PopulateInventory(result),
                new UiSideEffect.PublishOAuthStrategy(oauthStrategy));
    }

    @Test
    void connectSucceededWithoutOauthPopulatesInventoryOnly() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");
        ConnectionStatus connectedStatus = ConnectionStatus.connected(
                null, "mcp.example.com", null, 0);
        ConnectResult result = sampleResult(0);

        UiStateReducer.Reduction reduction = reducer.reduce(
                connecting,
                new UiAction.ConnectSucceeded(result, "mcp.example.com", connectedStatus, null));

        assertThat(reduction.state()).isInstanceOf(UiConnectionState.Connected.class);
        assertThat(reduction.sideEffects())
                .containsExactly(new UiSideEffect.PopulateInventory(result));
    }

    @Test
    void connectSucceededFromDisconnectedIsIgnoredAndLogsWarning() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectSucceeded(sampleResult(0), "h",
                        ConnectionStatus.connected(null, "h", null, 0), null));

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void connectFailedFromConnectingTransitionsToFailedAndClearsAutoDiscoveredOAuth() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.OAUTH, "OAuth: opening browser…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, new UiAction.ConnectFailed("scope rejected"));

        assertThat(result.state()).isEqualTo(UiConnectionState.failed(ConnectPhase.OAUTH, "scope rejected"));
        assertThat(result.sideEffects())
                .containsExactly(UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE);
    }

    @Test
    void connectFailedFromConnectingEmitsClearAutoDiscoveredOAuthFields() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.OAUTH, "OAuth: opening browser…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, new UiAction.ConnectFailed("user cancelled"));

        assertThat(result.sideEffects())
                .contains(UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE);
    }

    @Test
    void connectFailedFromDisconnectedIsIgnored() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(),
                new UiAction.ConnectFailed("anything"));

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects().get(0)).isInstanceOf(UiSideEffect.LogWarning.class);
    }

    @Test
    void disconnectRequestedFromConnectingCancelsWorkerRunsDisconnectAndClearsInventory() {
        AtomicInteger cancelCount = new AtomicInteger();
        Cancellable cancellable = cancelCount::incrementAndGet;
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), cancellable, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(
                connecting, UiAction.DisconnectRequested.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).containsExactly(
                new UiSideEffect.CancelConnect(cancellable),
                UiSideEffect.RunDisconnect.INSTANCE,
                UiSideEffect.ClearOAuthStrategy.INSTANCE,
                UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE,
                UiSideEffect.ClearInventory.INSTANCE);
    }

    @Test
    void disconnectRequestedFromConnectedRunsDisconnectClearsOauthAndInventory() {
        UiConnectionState connected = UiConnectionState.connected(
                sampleResult(2), "mcp.example.com",
                ConnectionStatus.connected(null, "mcp.example.com", null, 2));

        UiStateReducer.Reduction result = reducer.reduce(
                connected, UiAction.DisconnectRequested.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).containsExactly(
                UiSideEffect.RunDisconnect.INSTANCE,
                UiSideEffect.ClearOAuthStrategy.INSTANCE,
                UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE,
                UiSideEffect.ClearInventory.INSTANCE);
    }

    @Test
    void disconnectRequestedFromFailedRunsDisconnectClearsOauthAndInventory() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.failed(ConnectPhase.OAUTH, "boom"),
                UiAction.DisconnectRequested.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).contains(
                UiSideEffect.RunDisconnect.INSTANCE,
                UiSideEffect.ClearInventory.INSTANCE);
    }

    @Test
    void disconnectRequestedFromDisconnectedIsNoOp() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(), UiAction.DisconnectRequested.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).isEmpty();
    }

    @Test
    void externalDisconnectFromConnectedTransitionsToDisconnectedAndClearsInventory() {
        UiConnectionState connected = UiConnectionState.connected(
                sampleResult(0), "mcp.example.com",
                ConnectionStatus.connected(null, "mcp.example.com", null, 0));

        UiStateReducer.Reduction result = reducer.reduce(
                connected, UiAction.ExternalDisconnect.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).containsExactly(
                UiSideEffect.ClearOAuthStrategy.INSTANCE,
                UiSideEffect.ClearInventory.INSTANCE);
    }

    @Test
    void externalDisconnectFromConnectingIsIgnored() {
        UiConnectionState connecting = UiConnectionState.connecting(
                sampleAttempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");

        UiStateReducer.Reduction result = reducer.reduce(connecting, UiAction.ExternalDisconnect.INSTANCE);

        assertThat(result.state()).isSameAs(connecting);
        assertThat(result.sideEffects()).isEmpty();
    }

    @Test
    void externalDisconnectFromDisconnectedIsNoOp() {
        UiStateReducer.Reduction result = reducer.reduce(
                UiConnectionState.disconnected(), UiAction.ExternalDisconnect.INSTANCE);

        assertThat(result.state()).isEqualTo(UiConnectionState.disconnected());
        assertThat(result.sideEffects()).isEmpty();
    }

    private static ConnectAttempt sampleAttempt() {
        return ConnectAttempt.withSnapshot(
                "https://mcp.example.com/mcp", TransportType.STREAMABLE_HTTP, "mcp.example.com",
                "None", null);
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
