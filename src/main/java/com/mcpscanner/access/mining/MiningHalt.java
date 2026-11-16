package com.mcpscanner.access.mining;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

final class MiningHalt {

    private final BooleanSupplier cancelled;
    private final AtomicBoolean rateLimited = new AtomicBoolean();

    MiningHalt(BooleanSupplier cancelled) {
        this.cancelled = cancelled;
    }

    void rateLimited() {
        rateLimited.set(true);
    }

    Optional<MiningStop> stop() {
        if (cancelled.getAsBoolean()) {
            return Optional.of(MiningStop.CANCELLED);
        }
        return rateLimited.get() ? Optional.of(MiningStop.RATE_LIMITED) : Optional.empty();
    }
}
