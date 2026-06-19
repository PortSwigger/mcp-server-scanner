package com.mcpscanner.ui.state;

import java.util.ArrayList;
import java.util.List;

public final class UiStateReducer {

    public Reduction reduce(UiConnectionState state, UiAction action) {
        if (action instanceof UiAction.ConnectRequested cr) {
            return reduceConnectRequested(state, cr);
        }
        if (action instanceof UiAction.ConnectRejected cr) {
            return reduceConnectRejected(state, cr);
        }
        if (action instanceof UiAction.ConnectWorkerAttached attached) {
            return reduceConnectWorkerAttached(state, attached);
        }
        if (action instanceof UiAction.ConnectProgress progress) {
            return reduceConnectProgress(state, progress);
        }
        if (action instanceof UiAction.ConnectSucceeded succeeded) {
            return reduceConnectSucceeded(state, succeeded);
        }
        if (action instanceof UiAction.ConnectFailed failed) {
            return reduceConnectFailed(state, failed);
        }
        if (action instanceof UiAction.DisconnectRequested) {
            return reduceDisconnectRequested(state);
        }
        // UiAction is sealed; ExternalDisconnect is the only remaining permit
        return reduceExternalDisconnect(state);
    }

    private Reduction reduceConnectRequested(UiConnectionState state, UiAction.ConnectRequested action) {
        if (state instanceof UiConnectionState.Disconnected
                || state instanceof UiConnectionState.Failed
                || state instanceof UiConnectionState.Connected) {
            UiConnectionState next = UiConnectionState.connecting(
                    action.attempt(), Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…");
            return new Reduction(next, List.of(new UiSideEffect.SpawnConnectWorker(action.attempt())));
        }
        return ignored(state, "ConnectRequested", state);
    }

    private Reduction reduceConnectRejected(UiConnectionState state, UiAction.ConnectRejected action) {
        if (state instanceof UiConnectionState.Connecting) {
            return ignored(state, "ConnectRejected", state);
        }
        return new Reduction(UiConnectionState.failed(action.phase(), action.reason()), List.of());
    }

    private Reduction reduceConnectWorkerAttached(UiConnectionState state,
                                                  UiAction.ConnectWorkerAttached action) {
        if (state instanceof UiConnectionState.Connecting connecting) {
            return new Reduction(connecting.withCancellable(action.cancellable()), List.of());
        }
        return ignored(state, "ConnectWorkerAttached", state);
    }

    private Reduction reduceConnectProgress(UiConnectionState state, UiAction.ConnectProgress action) {
        if (state instanceof UiConnectionState.Connecting connecting) {
            return new Reduction(connecting.withProgress(action.phase(), action.message()), List.of());
        }
        return ignored(state, "ConnectProgress", state);
    }

    private Reduction reduceConnectSucceeded(UiConnectionState state, UiAction.ConnectSucceeded action) {
        if (state instanceof UiConnectionState.Connecting) {
            UiConnectionState connected = UiConnectionState.connected(
                    action.result(), action.host(), action.status());
            List<UiSideEffect> effects = new ArrayList<>();
            effects.add(new UiSideEffect.PopulateInventory(action.result()));
            if (action.oauthStrategy() != null) {
                effects.add(new UiSideEffect.PublishOAuthStrategy(action.oauthStrategy()));
            }
            return new Reduction(connected, List.copyOf(effects));
        }
        return ignored(state, "ConnectSucceeded", state);
    }

    private Reduction reduceConnectFailed(UiConnectionState state, UiAction.ConnectFailed action) {
        if (state instanceof UiConnectionState.Connecting connecting) {
            return new Reduction(
                    UiConnectionState.failed(connecting.phase(), action.reason()),
                    List.of(UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE));
        }
        return ignored(state, "ConnectFailed", state);
    }

    private Reduction reduceDisconnectRequested(UiConnectionState state) {
        if (state instanceof UiConnectionState.Disconnected) {
            return new Reduction(state, List.of());
        }
        if (state instanceof UiConnectionState.Connecting connecting) {
            return new Reduction(
                    UiConnectionState.disconnected(),
                    List.of(
                            new UiSideEffect.CancelConnect(connecting.cancellable()),
                            UiSideEffect.RunDisconnect.INSTANCE,
                            UiSideEffect.ClearOAuthStrategy.INSTANCE,
                            UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE,
                            UiSideEffect.ClearInventory.INSTANCE));
        }
        return new Reduction(
                UiConnectionState.disconnected(),
                List.of(
                        UiSideEffect.RunDisconnect.INSTANCE,
                        UiSideEffect.ClearOAuthStrategy.INSTANCE,
                        UiSideEffect.ClearAutoDiscoveredOAuthFields.INSTANCE,
                        UiSideEffect.ClearInventory.INSTANCE));
    }

    private Reduction reduceExternalDisconnect(UiConnectionState state) {
        if (state instanceof UiConnectionState.Disconnected) {
            return new Reduction(state, List.of());
        }
        if (state instanceof UiConnectionState.Connecting) {
            return new Reduction(state, List.of());
        }
        return new Reduction(
                UiConnectionState.disconnected(),
                List.of(UiSideEffect.ClearOAuthStrategy.INSTANCE, UiSideEffect.ClearInventory.INSTANCE));
    }

    private static Reduction ignored(UiConnectionState state, String actionName, UiConnectionState current) {
        String message = "Ignored " + actionName + " in state " + current.getClass().getSimpleName();
        return new Reduction(state, List.of(new UiSideEffect.LogWarning(message)));
    }

    public record Reduction(UiConnectionState state, List<UiSideEffect> sideEffects) {
    }
}
