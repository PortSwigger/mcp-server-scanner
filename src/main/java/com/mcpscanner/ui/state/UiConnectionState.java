package com.mcpscanner.ui.state;

import com.mcpscanner.client.ConnectResult;

public sealed interface UiConnectionState
        permits UiConnectionState.Disconnected,
                UiConnectionState.Connecting,
                UiConnectionState.Connected,
                UiConnectionState.Failed {

    ConnectionStatus status();

    static UiConnectionState disconnected() {
        return Disconnected.INSTANCE;
    }

    static UiConnectionState connecting(ConnectAttempt attempt, Cancellable cancellable,
                                        ConnectPhase phase, String message) {
        return new Connecting(attempt, cancellable, phase, message);
    }

    static UiConnectionState connected(ConnectResult result, String host, ConnectionStatus status) {
        return new Connected(result, host, status);
    }

    static UiConnectionState failed(ConnectPhase phase, String reason) {
        return new Failed(phase, reason);
    }

    record Disconnected() implements UiConnectionState {
        private static final Disconnected INSTANCE = new Disconnected();

        @Override
        public ConnectionStatus status() {
            return ConnectionStatus.disconnected();
        }
    }

    record Connecting(ConnectAttempt attempt, Cancellable cancellable, ConnectPhase phase, String message)
            implements UiConnectionState {

        public Connecting withCancellable(Cancellable replacement) {
            return new Connecting(attempt, replacement, phase, message);
        }

        public Connecting withProgress(ConnectPhase newPhase, String newMessage) {
            return new Connecting(attempt, cancellable, newPhase, newMessage);
        }

        @Override
        public ConnectionStatus status() {
            return ConnectionStatus.connecting(message);
        }
    }

    record Connected(ConnectResult result, String host, ConnectionStatus status)
            implements UiConnectionState {
    }

    record Failed(ConnectPhase phase, String reason) implements UiConnectionState {
        @Override
        public ConnectionStatus status() {
            return ConnectionStatus.failed(phase, reason);
        }
    }
}
