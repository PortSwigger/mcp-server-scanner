package com.mcpscanner.client;

public enum PingOutcome {
    ANSWERED,
    SESSION_REFUSED,
    UNREACHABLE,
    TIMED_OUT,
    INCONCLUSIVE;

    boolean provesLoss() {
        return this == SESSION_REFUSED;
    }

    boolean suggestsLoss() {
        return this == UNREACHABLE || this == TIMED_OUT;
    }
}
