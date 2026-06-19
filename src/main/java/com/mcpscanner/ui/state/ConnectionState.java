package com.mcpscanner.ui.state;

// Render-only projection of UiConnectionState; the source-of-truth state machine is UiConnectionState + UiStateReducer.
public enum ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    FAILED
}
