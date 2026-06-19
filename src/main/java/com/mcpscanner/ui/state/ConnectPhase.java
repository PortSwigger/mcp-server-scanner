package com.mcpscanner.ui.state;

public enum ConnectPhase {
    CONNECT("Connect"),
    DISCOVER("Discovery"),
    OAUTH("OAuth");

    private final String displayName;

    ConnectPhase(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
