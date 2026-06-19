package com.mcpscanner.ui.state;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.client.ConnectResult;

public sealed interface UiAction
        permits UiAction.ConnectRequested,
                UiAction.ConnectRejected,
                UiAction.ConnectWorkerAttached,
                UiAction.ConnectProgress,
                UiAction.ConnectSucceeded,
                UiAction.ConnectFailed,
                UiAction.DisconnectRequested,
                UiAction.ExternalDisconnect {

    record ConnectRequested(ConnectAttempt attempt) implements UiAction {
    }

    record ConnectRejected(ConnectPhase phase, String reason) implements UiAction {
    }

    record ConnectWorkerAttached(Cancellable cancellable) implements UiAction {
    }

    record ConnectProgress(ConnectPhase phase, String message) implements UiAction {
    }

    record ConnectSucceeded(ConnectResult result, String host, ConnectionStatus status,
                            OAuthAuthCodeStrategy oauthStrategy) implements UiAction {
    }

    record ConnectFailed(String reason) implements UiAction {
    }

    record DisconnectRequested() implements UiAction {
        public static final DisconnectRequested INSTANCE = new DisconnectRequested();
    }

    record ExternalDisconnect() implements UiAction {
        public static final ExternalDisconnect INSTANCE = new ExternalDisconnect();
    }
}
