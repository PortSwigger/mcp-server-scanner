package com.mcpscanner.ui.state;

import java.util.ArrayList;
import java.util.List;

public record ConnectionStatus(ConnectionState state, String message, String primaryButtonLabel) {

    private static final String SEPARATOR = " · ";
    private static final String LABEL_CONNECT = "Connect";
    private static final String LABEL_CANCEL = "Cancel";
    private static final String LABEL_DISCONNECT = "Disconnect";

    public static ConnectionStatus disconnected() {
        return new ConnectionStatus(ConnectionState.DISCONNECTED, "Disconnected", LABEL_CONNECT);
    }

    public static ConnectionStatus connecting(String progressDetail) {
        return new ConnectionStatus(ConnectionState.CONNECTING, progressDetail, LABEL_CANCEL);
    }

    public static ConnectionStatus connected(String subject, String host, Long expiresInMinutes, int toolCount) {
        return new ConnectionStatus(
                ConnectionState.CONNECTED,
                buildConnectedMessage(subject, host, expiresInMinutes, toolCount),
                LABEL_DISCONNECT);
    }

    public static ConnectionStatus failed(ConnectPhase phase, String reason) {
        return new ConnectionStatus(
                ConnectionState.FAILED, phase.displayName() + " failed: " + reason, LABEL_CONNECT);
    }

    public static ConnectionStatus scanLaunched(int toolCount) {
        String message = "Scan launched — " + toolCount + " tools queued. See Burp Dashboard for progress.";
        return new ConnectionStatus(ConnectionState.CONNECTED, message, LABEL_DISCONNECT);
    }

    public static ConnectionStatus scanFailed(String reason) {
        return new ConnectionStatus(ConnectionState.CONNECTED, "Scan failed: " + reason, LABEL_DISCONNECT);
    }

    public static ConnectionStatus authTerminallyFailed() {
        return new ConnectionStatus(
                ConnectionState.FAILED,
                "OAuth refresh failed; reconnect to continue",
                LABEL_CONNECT);
    }

    private static String buildConnectedMessage(String subject, String host, Long expiresInMinutes, int toolCount) {
        List<String> segments = new ArrayList<>();
        segments.add(subject == null
                ? "Connected to " + host
                : "Connected as " + subject + " to " + host);
        if (expiresInMinutes != null) {
            segments.add("expires in " + expiresInMinutes + " min");
        }
        segments.add(toolCount + " tools");
        return String.join(SEPARATOR, segments);
    }
}
