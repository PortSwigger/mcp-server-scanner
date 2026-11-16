package com.mcpscanner.checks.shared.collaborator;

import java.time.Duration;
import java.util.Objects;

public record InteractionWindow(Duration settle, Duration pollInterval) {

    private static final InteractionWindow STANDARD = new InteractionWindow(Duration.ofSeconds(3), Duration.ofSeconds(60));

    public InteractionWindow {
        Objects.requireNonNull(settle, "settle must not be null");
        Objects.requireNonNull(pollInterval, "pollInterval must not be null");
        if (pollInterval.isZero() || pollInterval.isNegative()) {
            throw new IllegalArgumentException("pollInterval must be positive");
        }
    }

    public static InteractionWindow standard() {
        return STANDARD;
    }
}
