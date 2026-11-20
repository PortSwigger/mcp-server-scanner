package com.mcpscanner.checks.api.crossidentity;

public final class TransportFailure {

    private volatile boolean raised;

    public boolean raised() {
        return raised;
    }

    public void raise() {
        raised = true;
    }
}
