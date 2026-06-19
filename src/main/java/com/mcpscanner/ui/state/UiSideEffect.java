package com.mcpscanner.ui.state;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;

import com.mcpscanner.client.ConnectResult;

public sealed interface UiSideEffect
        permits UiSideEffect.SpawnConnectWorker,
                UiSideEffect.CancelConnect,
                UiSideEffect.RunDisconnect,
                UiSideEffect.PublishOAuthStrategy,
                UiSideEffect.ClearOAuthStrategy,
                UiSideEffect.ClearAutoDiscoveredOAuthFields,
                UiSideEffect.PopulateInventory,
                UiSideEffect.ClearInventory,
                UiSideEffect.LogWarning {

    record SpawnConnectWorker(ConnectAttempt attempt) implements UiSideEffect {
    }

    record CancelConnect(Cancellable cancellable) implements UiSideEffect {
    }

    record RunDisconnect() implements UiSideEffect {
        public static final RunDisconnect INSTANCE = new RunDisconnect();
    }

    record PublishOAuthStrategy(OAuthAuthCodeStrategy strategy) implements UiSideEffect {
    }

    record ClearOAuthStrategy() implements UiSideEffect {
        public static final ClearOAuthStrategy INSTANCE = new ClearOAuthStrategy();
    }

    record ClearAutoDiscoveredOAuthFields() implements UiSideEffect {
        public static final ClearAutoDiscoveredOAuthFields INSTANCE = new ClearAutoDiscoveredOAuthFields();
    }

    record PopulateInventory(ConnectResult result) implements UiSideEffect {
    }

    record ClearInventory() implements UiSideEffect {
        public static final ClearInventory INSTANCE = new ClearInventory();
    }

    record LogWarning(String message) implements UiSideEffect {
    }
}
