package com.mcpscanner.ui.state;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionStatusTest {

    @Test
    void disconnectedStatusHasGrayDotAndDefaultText() {
        ConnectionStatus status = ConnectionStatus.disconnected();

        assertThat(status.state()).isEqualTo(ConnectionState.DISCONNECTED);
        assertThat(status.message()).isEqualTo("Disconnected");
    }

    @Test
    void connectingStatusCarriesProgressMessage() {
        ConnectionStatus status = ConnectionStatus.connecting("OAuth: awaiting browser callback");

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTING);
        assertThat(status.message()).contains("browser callback");
    }

    @Test
    void connectedStatusFormatsSubjectExpiryAndToolCount() {
        ConnectionStatus status = ConnectionStatus.connected(
                "user@example.com",
                "mcp.example.com",
                42L,
                30);

        assertThat(status.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(status.message()).isEqualTo(
                "Connected as user@example.com to mcp.example.com · expires in 42 min · 30 tools");
    }

    @Test
    void connectedStatusOmitsSubjectAndExpiryWhenAbsent() {
        ConnectionStatus status = ConnectionStatus.connected(null, "mcp.example.com", null, 5);

        assertThat(status.message()).isEqualTo("Connected to mcp.example.com · 5 tools");
    }

    @Test
    void failedStatusContainsPhaseAndReason() {
        ConnectionStatus status = ConnectionStatus.failed(
                ConnectPhase.OAUTH, "empty scope options are not supported for issuer https://x");

        assertThat(status.state()).isEqualTo(ConnectionState.FAILED);
        assertThat(status.message()).isEqualTo(
                "OAuth failed: empty scope options are not supported for issuer https://x");
    }

    @Test
    void scanLaunchedFactoryFormatsMessage() {
        ConnectionStatus s = ConnectionStatus.scanLaunched(7);
        assertThat(s.message()).isEqualTo(
                "Scan launched — 7 tools queued. See Burp Dashboard for progress.");
        assertThat(s.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(s.primaryButtonLabel()).isEqualTo("Disconnect");
    }

    @Test
    void scanFailedFactoryPreservesConnectedState() {
        ConnectionStatus s = ConnectionStatus.scanFailed("not connected");
        assertThat(s.state()).isEqualTo(ConnectionState.CONNECTED);
        assertThat(s.message()).isEqualTo("Scan failed: not connected");
        assertThat(s.primaryButtonLabel()).isEqualTo("Disconnect");
    }

    @Test
    void buttonLabelMatchesState() {
        assertThat(ConnectionStatus.disconnected().primaryButtonLabel()).isEqualTo("Connect");
        assertThat(ConnectionStatus.connecting("…").primaryButtonLabel()).isEqualTo("Cancel");
        assertThat(ConnectionStatus.connected(null, "h", null, 0).primaryButtonLabel())
                .isEqualTo("Disconnect");
        assertThat(ConnectionStatus.failed(ConnectPhase.OAUTH, "y").primaryButtonLabel()).isEqualTo("Connect");
    }

    @Test
    void connectingPrimaryButtonLabelIsCancel() {
        assertThat(ConnectionStatus.connecting("OAuth: opening browser…").primaryButtonLabel())
                .isEqualTo("Cancel");
    }
}
