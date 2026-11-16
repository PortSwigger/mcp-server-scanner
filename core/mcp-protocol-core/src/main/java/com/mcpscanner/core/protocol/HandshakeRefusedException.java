package com.mcpscanner.core.protocol;

public final class HandshakeRefusedException extends IllegalArgumentException {

    private final int status;

    HandshakeRefusedException(String stage, int status, boolean complete) {
        super(stage + " failed: HTTP " + status + (complete ? "" : " (incomplete)"));
        this.status = status;
    }

    public int status() {
        return status;
    }
}
